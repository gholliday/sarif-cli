using Sarif.Cli;

var rootCommand = CommandFactory.CreateRootCommand();
return await rootCommand.Parse(args).InvokeAsync();
