using Sarif.Cli;

// Spectre.Console writes UTF-8 box-drawing glyphs to stdout. On Windows, the
// console's OutputEncoding defaults to the legacy OEM code page (437/850/1252),
// which decodes those byte sequences as mojibake (Ú/Ä/Â etc.). Setting the
// in-process OutputEncoding to UTF-8 fixes this without touching the user's
// session (i.e. without a `chcp 65001`). Wrapped in try/catch because the
// setter throws when stdout is bound to a closed/redirected handle in some
// hosting scenarios.
if (OperatingSystem.IsWindows())
{
    try { Console.OutputEncoding = System.Text.Encoding.UTF8; }
    catch (System.IO.IOException) { }
}

var rootCommand = CommandFactory.CreateRootCommand();
return await rootCommand.Parse(args).InvokeAsync();
