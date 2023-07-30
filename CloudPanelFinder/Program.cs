using Spectre.Console;
using System.Collections.Concurrent;
using System.Net;
using System.Runtime.InteropServices;

namespace CloudPanelFinder
{
    internal static class Program
    {
        private static ConcurrentBag<string> VulnsInputted = new ConcurrentBag<string>();
        private static ConcurrentBag<string> VulnsFound = new ConcurrentBag<string>();
        private static int VulnsScanned = 0;
        private static int Vulns = 0;
        private static int VulnsFailed = 0;
        private static int Threads = 0;
        private static string fileName = "8443.txt";
        private static readonly object LogLock = new object();
        private static readonly string date = DateTime.Now.ToString("MM-dd-yyyy");
        private static readonly string UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36";
        static void UpdateTitle()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                Console.Title = $"Vulns Checked: {VulnsScanned}/{VulnsInputted.Count} Good: {Vulns} Failed:{VulnsFailed}";
        }

        [STAThread]
        static void Main(string[] args)
        {
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                Threads = Convert.ToInt32(args[0]);
            }

            AnsiConsole.Write(
                new FigletText("VulnChecker")
                    .LeftJustified()
                    .Color(Color.Magenta2));

            if (!File.Exists(fileName))
            {
                AnsiConsole.Write(new Markup($"[red]ERROR: {fileName} is missing.[/]"));
                Environment.Exit(0);
            }
            else
            {
                VulnsInputted = new ConcurrentBag<string>(File.ReadAllLines(fileName).Distinct());
            }

            if (!VulnsInputted.Any())
            {
                AnsiConsole.Write(new Markup($"[red]ERROR: we have no proxies to test.[/]"));
                Environment.Exit(0);
            }

            if (Threads == 0)
            {
                Threads = AnsiConsole.Ask<int>("How many [yellow]threads[/] ?");
            }

            AnsiConsole.Write(new Markup($"[yellow]Okay. {Threads}[/]\n"));

            Task.Run(() => PrintAccountProgress());

            Task.Run(() => MainJob(Threads)).Wait();
        }

        public static async void PrintAccountProgress()
        {
            try
            {
                await AnsiConsole.Progress()
                .AutoRefresh(true) // Turn off auto refresh
                .AutoClear(false)   // Do not remove the task list when done
                .HideCompleted(false)   // Hide tasks as they are completed
                .Columns(new ProgressColumn[]
                {
                new TaskDescriptionColumn(),    // Task description
                new ProgressBarColumn(),        // Progress bar
                new PercentageColumn(),         // Percentage
                new SpinnerColumn(Spinner.Known.Weather),            // Spinner
                })
                .StartAsync(async ctx =>
                {
                    var task1 = ctx.AddTask("[blue]Vulns Checked[/]", true, VulnsInputted.Count);

                    while (!ctx.IsFinished)
                    {
                        task1.Value = VulnsScanned;
                        await Task.Delay(100);
                    }
                });
            }
            catch (Exception)
            {
            }
        }
        public class HackerJson
        {
            public bool status { get; set; }
            public string msg { get; set; }
        }
        static async Task MainJob(int threads)
        {
            int threadLimit = threads;  // Change this to the number of threads you want
            SemaphoreSlim throttler = new SemaphoreSlim(threadLimit, threadLimit);

            List<Task> tasks = new List<Task>();

            foreach (var currentIP in VulnsInputted)
            {
                await throttler.WaitAsync();

                tasks.Add(
                    Task.Run(async () =>
                    {
                        try
                        {
                            await ScanIP(currentIP);
                        }
                        finally
                        {
                            throttler.Release();
                        }
                    })
                );
            }

            await Task.WhenAll(tasks);
        }

        static async Task ScanIP(string currentIP)
        {
            try
            {
                HttpClientHandler handler = new HttpClientHandler
                {
                    AutomaticDecompression = DecompressionMethods.All,
                    ServerCertificateCustomValidationCallback = (sender, cert, chain, sslPolicyErrors) => true
                };
                using HttpClient client = new HttpClient(handler);
                client.DefaultRequestHeaders.Add("User-Agent", UserAgent);
                client.Timeout = TimeSpan.FromSeconds(7);
                var response = await client.GetAsync($"https://{currentIP}:8443/admin/user/creation");
                if (response.StatusCode == HttpStatusCode.OK)
                {
                    var HttpContent = await response.Content.ReadAsStringAsync();

                    if (HttpContent != null && HttpContent.Contains("Admin User Creation"))
                    {
                        Interlocked.Increment(ref Vulns);
                        VulnsFound.Add(currentIP);
                        UpdateTitle();
                        lock (LogLock)
                        {
                            File.AppendAllText($"Vulns-{date}.txt", $"{currentIP}:8443/admin/user/creation\n");
                        }
                    }
                }
                else
                {
                    Interlocked.Increment(ref VulnsFailed);
                }
            }
            catch (Exception)
            {
                Interlocked.Increment(ref VulnsFailed);
            }
            Interlocked.Increment(ref VulnsScanned);
            UpdateTitle();
        }
    }
}