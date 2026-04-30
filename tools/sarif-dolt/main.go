package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	doltdriver "github.com/dolthub/driver"
)

type sqlExecutor interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

const (
	databaseName = "sarif"
	runID        = "default"
)

var validIdentifier = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

func main() {
	if len(os.Args) < 2 {
		usage(os.Stderr)
		os.Exit(2)
	}

	if err := run(context.Background(), os.Args[1], os.Args[2:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context, command string, args []string) error {
	switch command {
	case "init":
		return runInit(ctx, args)
	case "add-result":
		return runAddResult(ctx, args)
	case "add-results":
		return runAddResults(ctx, args)
	case "commit":
		return runCommit(ctx, args)
	case "diff":
		return runDiff(ctx, args)
	case "export":
		return runExport(ctx, args)
	case "-h", "--help", "help":
		usage(os.Stdout)
		return nil
	default:
		return fmt.Errorf("unknown command %q", command)
	}
}

func usage(w io.Writer) {
	fmt.Fprintln(w, "sarif-dolt is the optional embedded-Dolt storage helper for sarif-cli.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Commands:")
	fmt.Fprintln(w, "  init --store DIR --tool NAME [--tool-version VERSION] [--uri-base NAME=URI]")
	fmt.Fprintln(w, "  add-result --store DIR --rule-id ID --message TEXT [--file URI] [--start-line N]")
	fmt.Fprintln(w, "  add-results --store DIR --input RESULTS.jsonl")
	fmt.Fprintln(w, "  commit --store DIR --message TEXT [--allow-empty]")
	fmt.Fprintln(w, "  diff --store DIR [--from REV] [--to REV] [--format summary|text|json|tsv]")
	fmt.Fprintln(w, "  export --store DIR --output FILE")
}

func runInit(ctx context.Context, args []string) error {
	fs := newFlagSet("init")
	var store, tool, toolVersion, semanticVersion, organization, infoURI string
	var uriBases stringList
	fs.StringVar(&store, "store", ".sarif-dolt", "store directory")
	fs.StringVar(&tool, "tool", "", "tool driver name")
	fs.StringVar(&toolVersion, "tool-version", "", "tool driver version")
	fs.StringVar(&semanticVersion, "semantic-version", "", "tool semantic version")
	fs.StringVar(&organization, "organization", "", "tool organization")
	fs.StringVar(&infoURI, "info-uri", "", "tool information URI")
	fs.Var(&uriBases, "uri-base", "original URI base mapping NAME=URI")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(tool) == "" {
		return errors.New("--tool is required")
	}

	root, cleanupRoot, err := openRoot(ctx, store)
	if err != nil {
		return err
	}
	if _, err := root.ExecContext(ctx, "CREATE DATABASE IF NOT EXISTS `"+databaseName+"`"); err != nil {
		return errors.Join(err, cleanupRoot())
	}
	if err := cleanupRoot(); err != nil {
		return err
	}

	db, cleanup, err := openInitializedStore(ctx, store)
	if err != nil {
		return err
	}
	defer cleanup()

	if err := ensureSchema(ctx, db); err != nil {
		return err
	}

	uriBaseJSON, err := encodeURIBaseIDs(uriBases)
	if err != nil {
		return err
	}

	_, err = db.ExecContext(ctx, `
INSERT INTO runs
  (id, tool_name, tool_version, semantic_version, organization, information_uri, created_utc, original_uri_base_ids_json)
VALUES
  (?, ?, ?, ?, ?, ?, ?, ?)
ON DUPLICATE KEY UPDATE
  tool_name = VALUES(tool_name),
  tool_version = VALUES(tool_version),
  semantic_version = VALUES(semantic_version),
  organization = VALUES(organization),
  information_uri = VALUES(information_uri),
  original_uri_base_ids_json = VALUES(original_uri_base_ids_json)`,
		runID, tool, nullIfEmpty(toolVersion), nullIfEmpty(semanticVersion), nullIfEmpty(organization),
		nullIfEmpty(infoURI), time.Now().UTC(), nullIfEmpty(uriBaseJSON))
	if err != nil {
		return err
	}

	fmt.Printf("Initialized Dolt SARIF store at %s\n", store)
	return nil
}

func runAddResult(ctx context.Context, args []string) error {
	fs := newFlagSet("add-result")
	var store, ruleID, ruleName, message, level, fileURI, uriBaseID, snippet, securitySeverity, cvss string
	var startLine, startColumn, endLine, endColumn int
	var tags, properties stringList
	fs.StringVar(&store, "store", ".sarif-dolt", "store directory")
	fs.StringVar(&ruleID, "rule-id", "", "rule id")
	fs.StringVar(&ruleName, "rule-name", "", "rule name")
	fs.StringVar(&message, "message", "", "message text")
	fs.StringVar(&level, "level", "", "result level")
	fs.StringVar(&fileURI, "file", "", "file URI")
	fs.StringVar(&uriBaseID, "uri-base-id", "", "uri base id")
	fs.IntVar(&startLine, "start-line", 0, "start line")
	fs.IntVar(&startColumn, "start-column", 0, "start column")
	fs.IntVar(&endLine, "end-line", 0, "end line")
	fs.IntVar(&endColumn, "end-column", 0, "end column")
	fs.StringVar(&snippet, "snippet", "", "source snippet")
	fs.Var(&tags, "tag", "tag")
	fs.StringVar(&securitySeverity, "security-severity", "", "security severity")
	fs.StringVar(&cvss, "cvss", "", "CVSS vector")
	fs.Var(&properties, "property", "property key=value or key:json=<json>")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(ruleID) == "" {
		return errors.New("--rule-id is required")
	}
	if strings.TrimSpace(message) == "" {
		return errors.New("--message is required")
	}
	if level != "" && !isValidLevel(level) {
		return fmt.Errorf("invalid --level %q; use one of none, note, warning, error", level)
	}

	propsJSON, err := encodeProperties(properties, tags, securitySeverity, cvss)
	if err != nil {
		return err
	}

	db, cleanup, err := openInitializedStore(ctx, store)
	if err != nil {
		return err
	}
	defer cleanup()
	if err := ensureSchema(ctx, db); err != nil {
		return err
	}
	if err := ensureInitialized(ctx, db); err != nil {
		return err
	}

	input := resultInput{
		RuleID:           ruleID,
		RuleName:         ruleName,
		Message:          message,
		Level:            level,
		FileURI:          fileURI,
		URIBaseID:        uriBaseID,
		StartLine:        intPtrIfNonZero(startLine),
		StartColumn:      intPtrIfNonZero(startColumn),
		EndLine:          intPtrIfNonZero(endLine),
		EndColumn:        intPtrIfNonZero(endColumn),
		Snippet:          snippet,
		SecuritySeverity: securitySeverity,
		CVSS:             cvss,
		propertiesJSON:   propsJSON,
	}
	if err := validateResultInput(input, "--"); err != nil {
		return err
	}
	if err := ensureRule(ctx, db, input.RuleID, input.RuleName); err != nil {
		return err
	}
	id, err := insertResult(ctx, db, input)
	if err != nil {
		return err
	}

	fmt.Printf("Added result %s for rule %s\n", id, input.RuleID)
	return nil
}

func runAddResults(ctx context.Context, args []string) error {
	fs := newFlagSet("add-results")
	var store, inputPath string
	fs.StringVar(&store, "store", ".sarif-dolt", "store directory")
	fs.StringVar(&inputPath, "input", "", "JSONL input file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(inputPath) == "" {
		return errors.New("--input is required")
	}

	inputs, err := readResultInputs(inputPath)
	if err != nil {
		return err
	}

	db, cleanup, err := openInitializedStore(ctx, store)
	if err != nil {
		return err
	}
	defer cleanup()
	if err := ensureSchema(ctx, db); err != nil {
		return err
	}
	if err := ensureInitialized(ctx, db); err != nil {
		return err
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	ruleNames := make(map[string]string)
	for _, input := range inputs {
		if _, ok := ruleNames[input.RuleID]; !ok || ruleNames[input.RuleID] == "" {
			ruleNames[input.RuleID] = input.RuleName
		}
	}
	for ruleID, ruleName := range ruleNames {
		if err := ensureRule(ctx, tx, ruleID, ruleName); err != nil {
			return err
		}
	}
	for _, input := range inputs {
		if _, err := insertResult(ctx, tx, input); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}

	fmt.Printf("Added %d results\n", len(inputs))
	return nil
}

func runCommit(ctx context.Context, args []string) error {
	fs := newFlagSet("commit")
	var store, message string
	var allowEmpty bool
	fs.StringVar(&store, "store", ".sarif-dolt", "store directory")
	fs.StringVar(&message, "message", "", "commit message")
	fs.BoolVar(&allowEmpty, "allow-empty", false, "allow empty commit")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(message) == "" {
		return errors.New("--message is required")
	}

	db, cleanup, err := openInitializedStore(ctx, store)
	if err != nil {
		return err
	}
	defer cleanup()
	if err := ensureSchema(ctx, db); err != nil {
		return err
	}
	if err := ensureInitialized(ctx, db); err != nil {
		return err
	}

	if _, err := db.ExecContext(ctx, "CALL DOLT_ADD('-A')"); err != nil {
		return err
	}

	var commitArgs []any
	var placeholders string
	if allowEmpty {
		placeholders = "?, ?, ?"
		commitArgs = []any{"--allow-empty", "-m", message}
	} else {
		placeholders = "?, ?"
		commitArgs = []any{"-m", message}
	}
	if _, err := db.ExecContext(ctx, "CALL DOLT_COMMIT("+placeholders+")", commitArgs...); err != nil {
		return err
	}

	fmt.Println("Committed Dolt SARIF store")
	return nil
}

func runDiff(ctx context.Context, args []string) error {
	fs := newFlagSet("diff")
	var store, from, to, format string
	fs.StringVar(&store, "store", ".sarif-dolt", "store directory")
	fs.StringVar(&from, "from", "HEAD", "older revision")
	fs.StringVar(&to, "to", "WORKING", "newer revision")
	fs.StringVar(&format, "format", "summary", "output format: summary|text|rows|json|tsv")
	if err := fs.Parse(args); err != nil {
		return err
	}

	db, cleanup, err := openInitializedStore(ctx, store)
	if err != nil {
		return err
	}
	defer cleanup()
	if err := ensureSchema(ctx, db); err != nil {
		return err
	}
	if err := ensureInitialized(ctx, db); err != nil {
		return err
	}

	switch strings.ToLower(strings.TrimSpace(format)) {
	case "summary":
		return writeDiffSummary(ctx, db, from, to)
	case "text", "rows":
		return writeRowDiffText(ctx, db, from, to)
	case "json":
		return writeRowDiffJSON(ctx, db, from, to)
	case "tsv":
		return writeRowDiffTSV(ctx, db, from, to)
	default:
		return fmt.Errorf("unknown --format %q; use one of summary, text, rows, json, tsv", format)
	}
}

func writeDiffSummary(ctx context.Context, db *sql.DB, from, to string) error {
	rows, err := db.QueryContext(ctx, "SELECT * FROM dolt_diff_summary(?, ?)", from, to)
	if err != nil {
		return err
	}
	defer rows.Close()

	columns, err := rows.Columns()
	if err != nil {
		return err
	}
	fmt.Println(strings.Join(columns, "\t"))
	for rows.Next() {
		values := make([]sql.NullString, len(columns))
		scan := make([]any, len(columns))
		for i := range values {
			scan[i] = &values[i]
		}
		if err := rows.Scan(scan...); err != nil {
			return err
		}
		out := make([]string, len(columns))
		for i, value := range values {
			if value.Valid {
				out[i] = value.String
			}
		}
		fmt.Println(strings.Join(out, "\t"))
	}
	return rows.Err()
}

func writeRowDiffText(ctx context.Context, db *sql.DB, from, to string) error {
	records, err := loadRowDiffs(ctx, db, from, to)
	if err != nil {
		return err
	}
	if len(records) == 0 {
		fmt.Println("(no row changes)")
		return nil
	}
	for _, record := range records {
		switch record.Record {
		case "result":
			fmt.Printf("result %s id=%s ruleId=%s level=%s file=%s startLine=%s message=%s\n",
				record.ChangeType, record.ID, record.RuleID, record.Level, record.FileURI, intPtrString(record.StartLine), record.MessageText)
		case "rule":
			fmt.Printf("rule %s id=%s name=%s defaultLevel=%s\n",
				record.ChangeType, record.ID, record.Name, record.DefaultLevel)
		}
	}
	return nil
}

func writeRowDiffTSV(ctx context.Context, db *sql.DB, from, to string) error {
	records, err := loadRowDiffs(ctx, db, from, to)
	if err != nil {
		return err
	}
	fmt.Println("record\tchangeType\tid\truleId\tlevel\tfileUri\tstartLine\tmessageText\tname\tdefaultLevel")
	for _, record := range records {
		fmt.Printf("%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			tsvEscape(record.Record),
			tsvEscape(record.ChangeType),
			tsvEscape(record.ID),
			tsvEscape(record.RuleID),
			tsvEscape(record.Level),
			tsvEscape(record.FileURI),
			tsvEscape(intPtrString(record.StartLine)),
			tsvEscape(record.MessageText),
			tsvEscape(record.Name),
			tsvEscape(record.DefaultLevel))
	}
	return nil
}

func writeRowDiffJSON(ctx context.Context, db *sql.DB, from, to string) error {
	records, err := loadRowDiffs(ctx, db, from, to)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(records)
}

func loadRowDiffs(ctx context.Context, db *sql.DB, from, to string) ([]rowDiffRecord, error) {
	var records []rowDiffRecord
	rules, err := loadRuleDiffs(ctx, db, from, to)
	if err != nil {
		return nil, err
	}
	records = append(records, rules...)

	results, err := loadResultDiffs(ctx, db, from, to)
	if err != nil {
		return nil, err
	}
	records = append(records, results...)
	return records, nil
}

func loadRuleDiffs(ctx context.Context, db *sql.DB, from, to string) ([]rowDiffRecord, error) {
	query := fmt.Sprintf(`
SELECT diff_type, COALESCE(to_id, from_id), COALESCE(to_name, from_name), COALESCE(to_default_level, from_default_level)
FROM dolt_diff(%s, %s, 'rules')
ORDER BY COALESCE(to_id, from_id)`, sqlStringLiteral(from), sqlStringLiteral(to))
	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []rowDiffRecord
	for rows.Next() {
		var diffType, id, name, defaultLevel sql.NullString
		if err := rows.Scan(&diffType, &id, &name, &defaultLevel); err != nil {
			return nil, err
		}
		records = append(records, rowDiffRecord{
			Record:       "rule",
			ChangeType:   normalizeDiffType(nullStringValue(diffType)),
			ID:           nullStringValue(id),
			Name:         nullStringValue(name),
			DefaultLevel: nullStringValue(defaultLevel),
		})
	}
	return records, rows.Err()
}

func loadResultDiffs(ctx context.Context, db *sql.DB, from, to string) ([]rowDiffRecord, error) {
	query := fmt.Sprintf(`
SELECT diff_type,
       COALESCE(to_id, from_id),
       COALESCE(to_rule_id, from_rule_id),
       COALESCE(to_level, from_level),
       COALESCE(to_file_uri, from_file_uri),
       COALESCE(to_start_line, from_start_line),
       COALESCE(to_message_text, from_message_text)
FROM dolt_diff(%s, %s, 'results')
ORDER BY COALESCE(to_created_utc, from_created_utc), COALESCE(to_id, from_id)`, sqlStringLiteral(from), sqlStringLiteral(to))
	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []rowDiffRecord
	for rows.Next() {
		var diffType, id, ruleID, level, fileURI, messageText sql.NullString
		var startLine sql.NullInt64
		if err := rows.Scan(&diffType, &id, &ruleID, &level, &fileURI, &startLine, &messageText); err != nil {
			return nil, err
		}
		records = append(records, rowDiffRecord{
			Record:      "result",
			ChangeType:  normalizeDiffType(nullStringValue(diffType)),
			ID:          nullStringValue(id),
			RuleID:      nullStringValue(ruleID),
			Level:       nullStringValue(level),
			FileURI:     nullStringValue(fileURI),
			StartLine:   intPtrFromNull(startLine),
			MessageText: nullStringValue(messageText),
		})
	}
	return records, rows.Err()
}

func runExport(ctx context.Context, args []string) error {
	fs := newFlagSet("export")
	var store, output string
	fs.StringVar(&store, "store", ".sarif-dolt", "store directory")
	fs.StringVar(&output, "output", "", "SARIF output path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(output) == "" {
		return errors.New("--output is required")
	}

	db, cleanup, err := openInitializedStore(ctx, store)
	if err != nil {
		return err
	}
	defer cleanup()
	if err := ensureSchema(ctx, db); err != nil {
		return err
	}
	if err := ensureInitialized(ctx, db); err != nil {
		return err
	}

	log, err := exportSarif(ctx, db)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(output), 0o755); err != nil && filepath.Dir(output) != "." {
		return err
	}
	file, err := os.Create(output)
	if err != nil {
		return err
	}
	defer file.Close()

	enc := json.NewEncoder(file)
	enc.SetIndent("", "  ")
	if err := enc.Encode(log); err != nil {
		return err
	}

	fmt.Printf("Exported SARIF to %s\n", output)
	return nil
}

func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	return fs
}

func openRoot(ctx context.Context, store string) (*sql.DB, func() error, error) {
	return openDolt(ctx, store, "")
}

func openStore(ctx context.Context, store string) (*sql.DB, func() error, error) {
	return openDolt(ctx, store, databaseName)
}

func openInitializedStore(ctx context.Context, store string) (*sql.DB, func() error, error) {
	db, cleanup, err := openStore(ctx, store)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "database not found") {
			return nil, nil, errStoreNotInitialized()
		}
		return nil, nil, err
	}
	return db, cleanup, nil
}

func openDolt(ctx context.Context, store, database string) (*sql.DB, func() error, error) {
	dir, err := filepath.Abs(store)
	if err != nil {
		return nil, nil, err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, nil, err
	}
	if database != "" && !validIdentifier.MatchString(database) {
		return nil, nil, fmt.Errorf("invalid database name %q", database)
	}

	cfg, err := doltdriver.ParseDSN(buildDSN(dir, database))
	if err != nil {
		return nil, nil, err
	}
	connector, err := doltdriver.NewConnector(cfg)
	if err != nil {
		return nil, nil, err
	}

	db := sql.OpenDB(connector)
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	cleanup := func() error {
		dbErr := db.Close()
		connErr := connector.Close()
		if errors.Is(dbErr, context.Canceled) {
			dbErr = nil
		}
		if errors.Is(connErr, context.Canceled) {
			connErr = nil
		}
		return errors.Join(dbErr, connErr)
	}

	if err := db.PingContext(ctx); err != nil {
		return nil, nil, errors.Join(err, cleanup())
	}
	if database != "" {
		if _, err := db.ExecContext(ctx, "USE `"+database+"`"); err != nil {
			return nil, nil, errors.Join(err, cleanup())
		}
	}

	return db, cleanup, nil
}

func buildDSN(dir, database string) string {
	values := url.Values{}
	values.Set(doltdriver.CommitNameParam, "sarif-cli")
	values.Set(doltdriver.CommitEmailParam, "sarif-cli@local")
	values.Set(doltdriver.MultiStatementsParam, "true")
	if database != "" {
		values.Set(doltdriver.DatabaseParam, database)
	}

	path := dir
	if os.PathSeparator == '\\' {
		path = strings.ReplaceAll(path, `\`, `/`)
	}
	return "file://" + path + "?" + values.Encode()
}

func sqlStringLiteral(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}

func ensureSchema(ctx context.Context, db *sql.DB) error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS runs (
			id varchar(64) NOT NULL,
			tool_name varchar(255) NOT NULL,
			tool_version varchar(255),
			semantic_version varchar(255),
			organization varchar(255),
			information_uri text,
			created_utc datetime(6) NOT NULL,
			original_uri_base_ids_json json,
			properties_json json,
			PRIMARY KEY (id)
		)`,
		`CREATE TABLE IF NOT EXISTS rules (
			id varchar(512) NOT NULL,
			name text,
			short_description text,
			full_description text,
			help_uri text,
			default_level varchar(16) NOT NULL DEFAULT 'warning',
			properties_json json,
			PRIMARY KEY (id)
		)`,
		`CREATE TABLE IF NOT EXISTS results (
			id varchar(64) NOT NULL,
			rule_id varchar(512),
			level varchar(16),
			message_text text NOT NULL,
			file_uri text,
			uri_base_id varchar(255),
			start_line int,
			start_column int,
			end_line int,
			end_column int,
			snippet text,
			properties_json json,
			created_utc datetime(6) NOT NULL,
			PRIMARY KEY (id)
		)`,
	}
	for _, statement := range statements {
		if _, err := db.ExecContext(ctx, statement); err != nil {
			return err
		}
	}
	return nil
}

func ensureInitialized(ctx context.Context, db *sql.DB) error {
	var count int
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM runs WHERE id = ?", runID).Scan(&count); err != nil {
		return err
	}
	if count == 0 {
		return errStoreNotInitialized()
	}
	return nil
}

func errStoreNotInitialized() error {
	return errors.New("store is not initialized; run `sarif-cli db init` first")
}

func ensureRule(ctx context.Context, db sqlExecutor, ruleID, ruleName string) error {
	var count int
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM rules WHERE id = ?", ruleID).Scan(&count); err != nil {
		return err
	}
	if count == 0 {
		_, err := db.ExecContext(ctx, "INSERT INTO rules (id, name, default_level) VALUES (?, ?, 'warning')", ruleID, nullIfEmpty(ruleName))
		return err
	}
	if strings.TrimSpace(ruleName) != "" {
		_, err := db.ExecContext(ctx, "UPDATE rules SET name = COALESCE(name, ?) WHERE id = ?", ruleName, ruleID)
		return err
	}
	return nil
}

func readResultInputs(inputPath string) ([]resultInput, error) {
	file, err := os.Open(inputPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 16*1024*1024)
	var inputs []resultInput
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var input resultInput
		decoder := json.NewDecoder(strings.NewReader(line))
		decoder.UseNumber()
		if err := decoder.Decode(&input); err != nil {
			return nil, fmt.Errorf("line %d: invalid JSON: %w", lineNumber, err)
		}
		propertiesJSON, err := encodeJSONProperties(input.Properties, input.Tags, input.SecuritySeverity, input.CVSS)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNumber, err)
		}
		input.propertiesJSON = propertiesJSON
		if err := validateResultInput(input, fmt.Sprintf("line %d", lineNumber)); err != nil {
			return nil, err
		}
		inputs = append(inputs, input)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(inputs) == 0 {
		return nil, errors.New("--input did not contain any result records")
	}
	return inputs, nil
}

func validateResultInput(input resultInput, source string) error {
	if strings.TrimSpace(input.RuleID) == "" {
		return sourceError(source, "ruleId is required")
	}
	if strings.TrimSpace(input.Message) == "" {
		return sourceError(source, "message is required")
	}
	if input.Level != "" && !isValidLevel(input.Level) {
		return sourceError(source, fmt.Sprintf("invalid level %q; use one of none, note, warning, error", input.Level))
	}
	for name, value := range map[string]*int{
		"startLine":   input.StartLine,
		"startColumn": input.StartColumn,
		"endLine":     input.EndLine,
		"endColumn":   input.EndColumn,
	} {
		if value != nil && *value <= 0 {
			return sourceError(source, name+" must be positive")
		}
	}
	return nil
}

func sourceError(source, message string) error {
	if source == "" {
		return errors.New(message)
	}
	return fmt.Errorf("%s: %s", source, message)
}

func insertResult(ctx context.Context, db sqlExecutor, input resultInput) (string, error) {
	id, err := newID()
	if err != nil {
		return "", err
	}

	_, err = db.ExecContext(ctx, `
INSERT INTO results
  (id, rule_id, level, message_text, file_uri, uri_base_id, start_line, start_column, end_line, end_column, snippet, properties_json, created_utc)
VALUES
  (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, input.RuleID, nullIfEmpty(input.Level), input.Message, nullIfEmpty(input.FileURI), nullIfEmpty(input.URIBaseID),
		nullIfIntPtr(input.StartLine), nullIfIntPtr(input.StartColumn), nullIfIntPtr(input.EndLine), nullIfIntPtr(input.EndColumn),
		nullIfEmpty(input.Snippet), nullIfEmpty(input.propertiesJSON), time.Now().UTC())
	if err != nil {
		return "", err
	}
	return id, nil
}

func exportSarif(ctx context.Context, db *sql.DB) (sarifLog, error) {
	var toolVersion, semanticVersion, organization, informationURI, uriBasesJSON sql.NullString
	var toolName string
	err := db.QueryRowContext(ctx, `
SELECT tool_name, tool_version, semantic_version, organization, information_uri, original_uri_base_ids_json
FROM runs WHERE id = ?`, runID).Scan(&toolName, &toolVersion, &semanticVersion, &organization, &informationURI, &uriBasesJSON)
	if err != nil {
		return sarifLog{}, err
	}

	rules, ruleIndex, err := loadRules(ctx, db)
	if err != nil {
		return sarifLog{}, err
	}
	results, err := loadResults(ctx, db, ruleIndex)
	if err != nil {
		return sarifLog{}, err
	}
	uriBases, err := decodeURIBaseIDs(uriBasesJSON)
	if err != nil {
		return sarifLog{}, err
	}

	run := sarifRun{
		Tool: sarifTool{
			Driver: sarifDriver{
				Name:            toolName,
				Version:         nullStringValue(toolVersion),
				SemanticVersion: nullStringValue(semanticVersion),
				Organization:    nullStringValue(organization),
				InformationURI:  nullStringValue(informationURI),
				Rules:           rules,
			},
		},
		OriginalURIBaseIDs: uriBases,
		Results:            results,
	}

	return sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs:    []sarifRun{run},
	}, nil
}

func loadRules(ctx context.Context, db *sql.DB) ([]sarifRule, map[string]int, error) {
	rows, err := db.QueryContext(ctx, `
SELECT id, name, short_description, full_description, help_uri, default_level, properties_json
FROM rules ORDER BY id`)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()

	var rules []sarifRule
	index := map[string]int{}
	for rows.Next() {
		var id, defaultLevel string
		var name, shortDescription, fullDescription, helpURI, propsJSON sql.NullString
		if err := rows.Scan(&id, &name, &shortDescription, &fullDescription, &helpURI, &defaultLevel, &propsJSON); err != nil {
			return nil, nil, err
		}
		props, err := decodeProperties(propsJSON)
		if err != nil {
			return nil, nil, err
		}

		rule := sarifRule{
			ID:                   id,
			Name:                 nullStringValue(name),
			ShortDescription:     messageString(nullStringValue(shortDescription)),
			FullDescription:      messageString(nullStringValue(fullDescription)),
			HelpURI:              nullStringValue(helpURI),
			DefaultConfiguration: sarifReportingConfiguration{Level: defaultLevel},
			Properties:           props,
		}
		index[id] = len(rules)
		rules = append(rules, rule)
	}
	return rules, index, rows.Err()
}

func loadResults(ctx context.Context, db *sql.DB, ruleIndex map[string]int) ([]sarifResult, error) {
	rows, err := db.QueryContext(ctx, `
SELECT rule_id, level, message_text, file_uri, uri_base_id, start_line, start_column, end_line, end_column, snippet, properties_json
FROM results ORDER BY created_utc, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []sarifResult
	for rows.Next() {
		var ruleID, level, fileURI, uriBaseID, snippet, propsJSON sql.NullString
		var message string
		var startLine, startColumn, endLine, endColumn sql.NullInt64
		if err := rows.Scan(&ruleID, &level, &message, &fileURI, &uriBaseID, &startLine, &startColumn, &endLine, &endColumn, &snippet, &propsJSON); err != nil {
			return nil, err
		}
		props, err := decodeProperties(propsJSON)
		if err != nil {
			return nil, err
		}

		result := sarifResult{
			RuleID:     nullStringValue(ruleID),
			Level:      nullStringValue(level),
			Message:    sarifMessage{Text: message},
			Properties: props,
		}
		if idx, ok := ruleIndex[result.RuleID]; ok {
			result.RuleIndex = &idx
		}
		if fileURI.Valid && fileURI.String != "" {
			result.Locations = []sarifLocation{
				{
					PhysicalLocation: sarifPhysicalLocation{
						ArtifactLocation: sarifArtifactLocation{
							URI:       fileURI.String,
							URIBaseID: nullStringValue(uriBaseID),
						},
						Region: region(startLine, startColumn, endLine, endColumn, snippet),
					},
				},
			}
		}
		results = append(results, result)
	}
	return results, rows.Err()
}

func region(startLine, startColumn, endLine, endColumn sql.NullInt64, snippet sql.NullString) *sarifRegion {
	if !startLine.Valid && !startColumn.Valid && !endLine.Valid && !endColumn.Valid && !snippet.Valid {
		return nil
	}
	r := sarifRegion{
		StartLine:   intValue(startLine),
		StartColumn: intValue(startColumn),
		EndLine:     intValue(endLine),
		EndColumn:   intValue(endColumn),
	}
	if snippet.Valid {
		r.Snippet = &sarifArtifactContent{Text: snippet.String}
	}
	return &r
}

func encodeURIBaseIDs(values []string) (string, error) {
	if len(values) == 0 {
		return "", nil
	}
	uriBases := map[string]sarifArtifactLocation{}
	for _, value := range values {
		name, uri, ok := strings.Cut(value, "=")
		if !ok || strings.TrimSpace(name) == "" {
			return "", fmt.Errorf("--uri-base %q must be NAME=URI", value)
		}
		uriBases[name] = sarifArtifactLocation{URI: uri}
	}
	return encodeJSON(uriBases)
}

func decodeURIBaseIDs(value sql.NullString) (map[string]sarifArtifactLocation, error) {
	if !value.Valid || strings.TrimSpace(value.String) == "" {
		return nil, nil
	}
	var uriBases map[string]sarifArtifactLocation
	if err := json.Unmarshal([]byte(value.String), &uriBases); err != nil {
		return nil, err
	}
	return uriBases, nil
}

func encodeProperties(entries, tags []string, securitySeverity, cvss string) (string, error) {
	props := map[string]any{}
	for _, entry := range entries {
		key, rawValue, ok := strings.Cut(entry, "=")
		if !ok || key == "" {
			return "", fmt.Errorf("--property %q must be key=value or key:json=<raw json>", entry)
		}
		jsonMode := strings.HasSuffix(key, ":json")
		if jsonMode {
			key = strings.TrimSuffix(key, ":json")
			var value any
			decoder := json.NewDecoder(strings.NewReader(rawValue))
			decoder.UseNumber()
			if err := decoder.Decode(&value); err != nil {
				return "", fmt.Errorf("--property %s: %w", key, err)
			}
			props[key] = value
		} else {
			props[key] = autoType(rawValue)
		}
	}
	return encodeJSONProperties(props, tags, securitySeverity, cvss)
}

func encodeJSONProperties(properties map[string]any, tags []string, securitySeverity, cvss string) (string, error) {
	props := map[string]any{}
	for key, value := range properties {
		if strings.TrimSpace(key) == "" {
			return "", errors.New("properties cannot contain an empty key")
		}
		props[key] = value
	}
	if len(tags) > 0 {
		props["tags"] = []string(tags)
	}
	if securitySeverity != "" {
		props["security-severity"] = securitySeverity
	}
	if cvss != "" {
		props["cvssV3_1"] = cvss
	}
	if len(props) == 0 {
		return "", nil
	}
	return encodeJSON(props)
}

func decodeProperties(value sql.NullString) (map[string]any, error) {
	if !value.Valid || strings.TrimSpace(value.String) == "" {
		return nil, nil
	}
	props := map[string]any{}
	if err := json.Unmarshal([]byte(value.String), &props); err != nil {
		return nil, err
	}
	return props, nil
}

func autoType(raw string) any {
	if raw == "" {
		return ""
	}
	if raw == "true" {
		return true
	}
	if raw == "false" {
		return false
	}
	if i, err := strconv.ParseInt(raw, 10, 64); err == nil {
		return i
	}
	if f, err := strconv.ParseFloat(raw, 64); err == nil {
		return f
	}
	return raw
}

func encodeJSON(value any) (string, error) {
	bytes, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

func newID() (string, error) {
	var bytes [16]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes[:]), nil
}

func isValidLevel(level string) bool {
	switch level {
	case "none", "note", "warning", "error":
		return true
	default:
		return false
	}
}

func nullIfEmpty(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func nullIfZero(value int) any {
	if value == 0 {
		return nil
	}
	return value
}

func nullIfIntPtr(value *int) any {
	if value == nil {
		return nil
	}
	return *value
}

func intPtrIfNonZero(value int) *int {
	if value == 0 {
		return nil
	}
	return &value
}

func intPtrFromNull(value sql.NullInt64) *int {
	if !value.Valid {
		return nil
	}
	i := int(value.Int64)
	return &i
}

func nullStringValue(value sql.NullString) string {
	if !value.Valid {
		return ""
	}
	return value.String
}

func intValue(value sql.NullInt64) int {
	if !value.Valid {
		return 0
	}
	return int(value.Int64)
}

func messageString(text string) *sarifMessageString {
	if text == "" {
		return nil
	}
	return &sarifMessageString{Text: text}
}

func normalizeDiffType(value string) string {
	switch strings.ToLower(value) {
	case "added":
		return "inserted"
	case "removed":
		return "deleted"
	default:
		return strings.ToLower(value)
	}
}

func intPtrString(value *int) string {
	if value == nil {
		return ""
	}
	return strconv.Itoa(*value)
}

func tsvEscape(value string) string {
	value = strings.ReplaceAll(value, "\t", " ")
	value = strings.ReplaceAll(value, "\r", " ")
	value = strings.ReplaceAll(value, "\n", " ")
	return value
}

type stringList []string

func (s *stringList) String() string {
	return strings.Join(*s, ",")
}

func (s *stringList) Set(value string) error {
	*s = append(*s, value)
	return nil
}

type resultInput struct {
	RuleID           string         `json:"ruleId"`
	RuleName         string         `json:"ruleName,omitempty"`
	Message          string         `json:"message"`
	Level            string         `json:"level,omitempty"`
	FileURI          string         `json:"file,omitempty"`
	URIBaseID        string         `json:"uriBaseId,omitempty"`
	StartLine        *int           `json:"startLine,omitempty"`
	StartColumn      *int           `json:"startColumn,omitempty"`
	EndLine          *int           `json:"endLine,omitempty"`
	EndColumn        *int           `json:"endColumn,omitempty"`
	Snippet          string         `json:"snippet,omitempty"`
	Tags             []string       `json:"tags,omitempty"`
	Properties       map[string]any `json:"properties,omitempty"`
	SecuritySeverity string         `json:"securitySeverity,omitempty"`
	CVSS             string         `json:"cvss,omitempty"`
	propertiesJSON   string
}

type rowDiffRecord struct {
	Record       string `json:"record"`
	ChangeType   string `json:"changeType"`
	ID           string `json:"id"`
	RuleID       string `json:"ruleId,omitempty"`
	Level        string `json:"level,omitempty"`
	FileURI      string `json:"fileUri,omitempty"`
	StartLine    *int   `json:"startLine,omitempty"`
	MessageText  string `json:"messageText,omitempty"`
	Name         string `json:"name,omitempty"`
	DefaultLevel string `json:"defaultLevel,omitempty"`
}

type sarifLog struct {
	Schema  string     `json:"$schema,omitempty"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool               sarifTool                        `json:"tool"`
	OriginalURIBaseIDs map[string]sarifArtifactLocation `json:"originalUriBaseIds,omitempty"`
	Results            []sarifResult                    `json:"results,omitempty"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name            string      `json:"name"`
	Version         string      `json:"version,omitempty"`
	SemanticVersion string      `json:"semanticVersion,omitempty"`
	Organization    string      `json:"organization,omitempty"`
	InformationURI  string      `json:"informationUri,omitempty"`
	Rules           []sarifRule `json:"rules,omitempty"`
}

type sarifRule struct {
	ID                   string                      `json:"id"`
	Name                 string                      `json:"name,omitempty"`
	ShortDescription     *sarifMessageString         `json:"shortDescription,omitempty"`
	FullDescription      *sarifMessageString         `json:"fullDescription,omitempty"`
	HelpURI              string                      `json:"helpUri,omitempty"`
	DefaultConfiguration sarifReportingConfiguration `json:"defaultConfiguration,omitempty"`
	Properties           map[string]any              `json:"properties,omitempty"`
}

type sarifReportingConfiguration struct {
	Level string `json:"level,omitempty"`
}

type sarifMessageString struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID     string          `json:"ruleId,omitempty"`
	RuleIndex  *int            `json:"ruleIndex,omitempty"`
	Level      string          `json:"level,omitempty"`
	Message    sarifMessage    `json:"message"`
	Locations  []sarifLocation `json:"locations,omitempty"`
	Properties map[string]any  `json:"properties,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           *sarifRegion          `json:"region,omitempty"`
}

type sarifArtifactLocation struct {
	URI       string `json:"uri,omitempty"`
	URIBaseID string `json:"uriBaseId,omitempty"`
}

type sarifRegion struct {
	StartLine   int                   `json:"startLine,omitempty"`
	StartColumn int                   `json:"startColumn,omitempty"`
	EndLine     int                   `json:"endLine,omitempty"`
	EndColumn   int                   `json:"endColumn,omitempty"`
	Snippet     *sarifArtifactContent `json:"snippet,omitempty"`
}

type sarifArtifactContent struct {
	Text string `json:"text"`
}
