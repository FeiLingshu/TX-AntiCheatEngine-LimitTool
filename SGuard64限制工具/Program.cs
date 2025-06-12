using Microsoft.Win32;
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Management;
using System.Runtime.InteropServices;
using System.ServiceProcess;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace SGuard64_LimitTool
{
    internal class Program
    {
        internal const string GUID = "78798E28-2236-41DC-A3AF-D415C5ED397C";
        internal static EventWaitHandle ProgramStarted;
        [STAThread]
        internal static void Main(string[] _)
        {
            ProgramStarted = new EventWaitHandle(false, EventResetMode.AutoReset, GUID, out bool createNew);
            if (!createNew)
            {
                ProgramStarted.Set();
                return;
            }
            ThreadPool.RegisterWaitForSingleObject(ProgramStarted, OnProgramStarted, null, -1, false);
            SetProcessEcoQoS(Process.GetCurrentProcess().Handle, true);
            AutoResetEvent watchertimer = new AutoResetEvent(false);
            MEWatcher watcher = new MEWatcher(watchertimer);
            do
            {
                if (string.IsNullOrEmpty((string)Registry.GetValue(
                    "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\AntiCheatExpert Service", "ImagePath", string.Empty)))
                {
                    watcher.StartWatcher();
                    watcher.runcount = true;
                    watchertimer.WaitOne();
                    watcher.CloseWatcher();
                    GC.KeepAlive(watcher);
                    GC.Collect();
                }
                ManagementObjectSearcher searcher = new ManagementObjectSearcher("select * from Win32_Processor");
                int corecount = 0;
                foreach (ManagementBaseObject obj in searcher.Get())
                {
                    object cores = obj["NumberOfCores"];
                    if (cores == null)
                    {
                        continue;
                    }
                    bool success = int.TryParse(cores.ToString(), out int coreCount);
                    if (success)
                    {
                        corecount += coreCount;
                    }
                }
                int processorcount = Environment.ProcessorCount;
                bool corestate = processorcount <= 64;
                uint processormask = 0U;
                if (corestate)
                {
                    bool reportcheck = processorcount >= corecount && processorcount <= corecount * 2;
                    if (!reportcheck || corecount == processorcount || corecount * 2 == processorcount)
                    {
                        processormask |= (1U << (processorcount - 1));
                    }
                    else
                    {
                        for (int i = processorcount - (corecount * 2 - processorcount); i < processorcount; i++)
                        {
                            processormask |= (1U << i);
                        }
                    }
                }
                try
                {
                    ServiceController sc = new ServiceController("AntiCheatExpert Service");
                    sc.WaitForStatus(ServiceControllerStatus.Running);
                    string reg = (string)Registry.GetValue("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\AntiCheatExpert Service", "ImagePath", string.Empty);
                    string path = Regex.Replace(reg, @" -autorun\Z", string.Empty).Trim('"');
                    ProcessInfo pi = new ProcessInfo(null, null, corestate, processormask, path);
                    if (File.Exists(path) && File.Exists($"{new FileInfo(path).Directory}\\SGuard64.exe"))
                    {
                        bool check = false;
                        AutoResetEvent timer = new AutoResetEvent(false);
                        do
                        {
                            Process[] processes = Process.GetProcessesByName("SGuard64");
                            foreach (Process process in processes)
                            {
                                if (GetProcessFilename(process) == $"{new FileInfo(path).Directory}\\SGuard64.exe")
                                {
                                    pi.process1 = process;
                                    check = Set(process, corestate, processormask);
                                    break;
                                }
                            }
                            timer.WaitOne(100);
                        } while (sc.Status == ServiceControllerStatus.Running && !check);
                    }
                    if (File.Exists(path) && File.Exists($"{new FileInfo(path).Directory}\\SGuardSvc64.exe"))
                    {
                        bool check = false;
                        AutoResetEvent timer = new AutoResetEvent(false);
                        do
                        {
                            Process[] processes = Process.GetProcessesByName("SGuardSvc64");
                            foreach (Process process in processes)
                            {
                                if (GetProcessFilename(process) == $"{new FileInfo(path).Directory}\\SGuardSvc64.exe")
                                {
                                    pi.process2 = process;
                                    check = Set(process, corestate, processormask);
                                    break;
                                }
                            }
                            timer.WaitOne(100);
                        } while (sc.Status == ServiceControllerStatus.Running && !check);
                    }
                    Thread[] ts = CheckLoop(pi);
                    sc.WaitForStatus(ServiceControllerStatus.Stopped);
                    foreach (Thread t in ts)
                    {
                        if (t.IsAlive)
                        {
                            t.Abort();
                        }
                    }
                }
                catch (Exception)
                {
                    continue;
                }
            } while (Thread.CurrentThread.IsAlive);
        }
        private struct ProcessInfo
        {
            internal Process process1;
            internal Process process2;
            internal bool corestate;
            internal uint processormask;
            internal string __path;
            internal ProcessInfo(Process process1, Process process2, bool corestate, uint processormask, string __path)
            {
                this.process1 = process1;
                this.process2 = process2;
                this.corestate = corestate;
                this.processormask = processormask;
                this.__path = __path;
            }
        }
        private static bool Set(Process process, bool corestate, uint processormask)
        {
            process.PriorityClass = ProcessPriorityClass.Idle;
            if (corestate) SetProcessAffinityMask(process.Handle, processormask);
            SetProcessEcoQoS(process.Handle, true);
            Exception exception = JobObject.Go("SBTX&SBACE&FKU", process.Handle);
            if (Debugger.IsAttached && exception != null) Console.WriteLine(exception.Message);
            return true;
        }
        private static Thread[] CheckLoop(ProcessInfo processinfo)
        {
            Thread thread = new Thread(() =>
            {
                AutoResetEvent timer = new AutoResetEvent(false);
                do
                {
                    timer.WaitOne(new TimeSpan(0, 1, 0));
                    //timer.WaitOne(100); // for test
                    if (!Thread.CurrentThread.IsAlive) break;
                    Process p1 = Interlocked.CompareExchange(ref processinfo.process1, null, null);
                    Process p2 = Interlocked.CompareExchange(ref processinfo.process2, null, null);
                    if (p1 != null)
                    {
                        Set(p1, processinfo.corestate, processinfo.processormask);
                    }
                    if (p2 != null)
                    {
                        Set(p2, processinfo.corestate, processinfo.processormask);
                    }
                    GC.Collect();
                } while (Thread.CurrentThread.IsAlive);
            })
            { IsBackground = true };

            Thread t_a = new Thread(() =>
            {
                do
                {
                    Process p = Interlocked.CompareExchange(ref processinfo.process1, null, null);
                    p.WaitForExit();
                    Interlocked.Exchange(ref processinfo.process1, null);
                    AutoResetEvent timer = new AutoResetEvent(false);
                    do
                    {
                        Process[] processes = Process.GetProcessesByName("SGuard64");
                        foreach (Process process in processes)
                        {
                            if (GetProcessFilename(process) == $"{new FileInfo(processinfo.__path).Directory}\\SGuard64.exe")
                            {
                                Interlocked.Exchange(ref processinfo.process1, process);
                                Set(process, processinfo.corestate, processinfo.processormask);
                                GC.Collect();
                                break;
                            }
                        }
                        timer.WaitOne(1000);
                    } while (Thread.CurrentThread.IsAlive);
                } while (Thread.CurrentThread.IsAlive);
            })
            { IsBackground = true };

            Thread t_b = new Thread(() =>
            {
                do
                {
                    Process p = Interlocked.CompareExchange(ref processinfo.process2, null, null);
                    p.WaitForExit();
                    Interlocked.Exchange(ref processinfo.process2, null);
                    AutoResetEvent timer = new AutoResetEvent(false);
                    do
                    {
                        Process[] processes = Process.GetProcessesByName("SGuardSvc64");
                        foreach (Process process in processes)
                        {
                            if (GetProcessFilename(process) == $"{new FileInfo(processinfo.__path).Directory}\\SGuardSvc64.exe")
                            {
                                Interlocked.Exchange(ref processinfo.process2, process);
                                Set(process, processinfo.corestate, processinfo.processormask);
                                GC.Collect();
                                break;
                            }
                        }
                        timer.WaitOne(1000);
                    } while (Thread.CurrentThread.IsAlive);
                } while (Thread.CurrentThread.IsAlive);
            })
            { IsBackground = true };

            thread.Start();
            if (Interlocked.CompareExchange(ref processinfo.process1, null, null) != null)
            {
                t_a.Start();
            }
            if (Interlocked.CompareExchange(ref processinfo.process2, null, null) != null)
            {
                t_b.Start();
            }

            return new Thread[3] { thread, t_a, t_b };
        }
        private static void OnProgramStarted(object state, bool timeout)
        {
            // Do Nothing ...
            return;
        }
        [Flags]
        private enum ProcessAccessFlags : uint
        {
            QueryLimitedInformation = 0x00001000
        }
        [DllImport("kernel32.dll")]
        private static extern bool QueryFullProcessImageName(
            [In] IntPtr hProcess,
            [In] int dwFlags,
            [Out] StringBuilder lpExeName,
            ref int lpdwSize);
        [DllImport("kernel32.dll")]
        private static extern IntPtr OpenProcess(
            ProcessAccessFlags processAccess,
            bool bInheritHandle,
            int processId);
        private static string GetProcessFilename(Process p)
        {
            int capacity = 2048;
            StringBuilder builder = new StringBuilder(capacity);
            IntPtr ptr = OpenProcess(ProcessAccessFlags.QueryLimitedInformation, false, p.Id);
            if (!QueryFullProcessImageName(ptr, 0, builder, ref capacity))
            {
                return string.Empty;
            }
            return builder.ToString();
        }
        [DllImport("kernel32.dll")]
        private static extern ulong SetProcessAffinityMask(IntPtr hProcess, ulong dwProcessAffinityMask);
        private static bool SetProcessEcoQoS(IntPtr hProcess, bool bFlag)
        {
            // 此结构有三个字段Version，ControlMask 和 StateMask
            uint version = 1;
            uint controlMask = 0x1; //非权重开关
            uint stateMask = (uint)(bFlag ? 0x1 : 0x0);
            int szControlBlock = 12; // 三个uint的大小
            IntPtr homo = Marshal.AllocHGlobal(szControlBlock);
            Marshal.WriteInt32(homo, (int)version); //homo 指向内存块开头
            Marshal.WriteInt32(homo + 4, (int)controlMask); // 将 controlMask 值写入第2字段地址，需将 homo 指针加4字节
            Marshal.WriteInt32(homo + 8, (int)stateMask); // 将 stateMask 值写入第3个字段地址，需将 homo 指针加8个字节
            bool result = true;
            result &= SetProcessInformation(hProcess, PROCESS_INFORMATION_CLASS.ProcessPowerThrottling, homo, (uint)szControlBlock);
            result &= SetPriorityClass(hProcess, (uint)(bFlag ? 0x40 : 0x20));
            Marshal.FreeHGlobal(homo);
            return result;
        }
        [DllImport("kernel32.dll")]
        private static extern bool SetProcessInformation([In] IntPtr hProcess,
            [In] PROCESS_INFORMATION_CLASS ProcessInformationClass, IntPtr ProcessInformation, uint ProcessInformationSize);
        [DllImport("kernel32.dll")]
        private static extern bool SetPriorityClass(IntPtr handle, uint priorityClass);
        private enum PROCESS_INFORMATION_CLASS
        {
            ProcessMemoryPriority,
            ProcessMemoryExhaustionInfo,
            ProcessAppMemoryInfo,
            ProcessInPrivateInfo,
            ProcessPowerThrottling,
            ProcessReservedValue1,
            ProcessTelemetryCoverageInfo,
            ProcessProtectionLevelInfo,
            ProcessLeapSecondInfo,
            ProcessInformationClassMax,
        }
    }
    internal class MEWatcher
    {
        internal MEWatcher(AutoResetEvent timer)
        {
            this.timer = timer;
        }
        internal bool runcount = true;
        private readonly AutoResetEvent timer = null;
        private ManagementEventWatcher eventWatcher = null;
        private EventArrivedEventHandler handle = null;
        internal void StartWatcher()
        {
            try
            {
                string selecrtext = $@"SELECT * FROM RegistryValueChangeEvent WHERE Hive='HKEY_LOCAL_MACHINE' AND KeyPath='SYSTEM\\CurrentControlSet\\Services\\AntiCheatExpert Service' AND ValueName='ImagePath'";
                WqlEventQuery regQuery = new WqlEventQuery(selecrtext);
                eventWatcher = new ManagementEventWatcher(regQuery);
                handle = new EventArrivedEventHandler(HandleEvent);
                eventWatcher.EventArrived += handle;
                eventWatcher.Start();
            }
            catch (Exception)
            {
                // Do Nothing ...
            }
        }
        internal void CloseWatcher()
        {
            try
            {
                if (eventWatcher != null)
                {
                    eventWatcher.EventArrived -= handle;
                    handle = null;
                    eventWatcher.Stop();
                    eventWatcher.Dispose();
                    eventWatcher = null;
                }
            }
            catch (Exception)
            {
                eventWatcher = null;
            }
        }
        internal void HandleEvent(object sender, EventArrivedEventArgs e)
        {
            string reg = (string)Registry.GetValue("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\AntiCheatExpert Service", "ImagePath", string.Empty);
            string path = Regex.Replace(reg, @" -autorun\Z", string.Empty).Trim('"');
            if (File.Exists(path) && File.Exists($"{new FileInfo(path).Directory}\\SGuard64.exe") && File.Exists($"{new FileInfo(path).Directory}\\SGuardSvc64.exe"))
            {
                new AutoResetEvent(false).WaitOne(100);
                if (runcount)
                {
                    timer.Set();
                    runcount = false;
                }
            }
        }
    }

    internal static class JobObject
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        private static extern IntPtr CreateJobObject(IntPtr securityAttributes, string name);
        [StructLayout(LayoutKind.Explicit)]
        private struct JOBOBJECT_CPU_RATE_CONTROL_INFORMATION
        {
            [FieldOffset(0)]
            internal uint ControlFlags;
            [FieldOffset(4)]
            internal uint CpuRate;
            [FieldOffset(4)]
            internal uint Weight;
            [FieldOffset(4)]
            internal ushort MinRate;
            [FieldOffset(6)]
            internal ushort MaxRate;
        }
        public const uint JOB_OBJECT_CPU_RATE_CONTROL_ENABLE = 0x00000001;
        public const uint JOB_OBJECT_CPU_RATE_CONTROL_MIN_MAX_RATE = 0x00000010;
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetInformationJobObject(
            IntPtr hJob,
            JobObjectInfoType infoType,
            IntPtr lpJobObjectInfo,
            uint cbJobObjectInfoLength);
        private enum JobObjectInfoType
        {
            JobObjectCpuRateControlInformation = 15
        }
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool AssignProcessToJobObject(IntPtr jobHandle, IntPtr processHandle);
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr hObject);
        internal static Exception Go(string GUID, IntPtr phandle)
        {
            Exception exp = null;
            var jobHandle = CreateJobObject(IntPtr.Zero, GUID);
            try
            {
                if (jobHandle == IntPtr.Zero)
                {
                    throw new ArgumentNullException($"Can Not Create JobObject [Name = {GUID}]");
                };
                JOBOBJECT_CPU_RATE_CONTROL_INFORMATION cpuInfo = new JOBOBJECT_CPU_RATE_CONTROL_INFORMATION()
                {
                    ControlFlags = JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | JOB_OBJECT_CPU_RATE_CONTROL_MIN_MAX_RATE,
                    MinRate = 1,
                    MaxRate = 100
                };
                var CpuLimitInfoPtr = Marshal.AllocHGlobal(Marshal.SizeOf(cpuInfo));
                Marshal.StructureToPtr(cpuInfo, CpuLimitInfoPtr, false);
                if (!SetInformationJobObject(jobHandle, JobObjectInfoType.JobObjectCpuRateControlInformation, CpuLimitInfoPtr, (uint)Marshal.SizeOf(cpuInfo)))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
                Marshal.FreeHGlobal(CpuLimitInfoPtr);
                if (!AssignProcessToJobObject(jobHandle, phandle))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
            }
            catch (Exception e)
            {
                exp = e;
            }
            finally
            {
                CloseHandle(jobHandle);
            }
            return exp;
        }
    }
}
