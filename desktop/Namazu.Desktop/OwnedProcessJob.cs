using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Namazu.Desktop;

internal sealed class OwnedProcessJob : IDisposable
{
    private readonly SafeFileHandle handle;
    internal OwnedProcessJob()
    {
        handle = CreateJobObject(IntPtr.Zero, null);
        if (handle.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
        var limits = new ExtendedLimitInformation();
        limits.BasicLimitInformation.LimitFlags = 0x00002000; // KILL_ON_JOB_CLOSE
        int size = Marshal.SizeOf<ExtendedLimitInformation>();
        IntPtr data = Marshal.AllocHGlobal(size);
        try
        {
            Marshal.StructureToPtr(limits, data, false);
            if (!SetInformationJobObject(handle, 9, data, (uint)size))
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }
        finally { Marshal.FreeHGlobal(data); }
    }

    internal void Own(Process process)
    {
        if (!AssignProcessToJobObject(handle, process.Handle))
            throw new Win32Exception(Marshal.GetLastWin32Error());
    }

    public void Dispose() => handle.Dispose();

    [StructLayout(LayoutKind.Sequential)]
    private struct BasicLimitInformation
    {
        public long PerProcessUserTimeLimit, PerJobUserTimeLimit;
        public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize, MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass, SchedulingClass;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct IoCounters { public ulong ReadOperationCount, WriteOperationCount, OtherOperationCount, ReadTransferCount, WriteTransferCount, OtherTransferCount; }
    [StructLayout(LayoutKind.Sequential)]
    private struct ExtendedLimitInformation
    {
        public BasicLimitInformation BasicLimitInformation;
        public IoCounters IoInfo;
        public UIntPtr ProcessMemoryLimit, JobMemoryLimit, PeakProcessMemoryUsed, PeakJobMemoryUsed;
    }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateJobObject(IntPtr attributes, string? name);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetInformationJobObject(SafeFileHandle job, int informationClass, IntPtr information, uint length);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AssignProcessToJobObject(SafeFileHandle job, IntPtr process);
}
