using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace ptpwn
{
    class Program
    {
        static void Main(string[] args)
        {
            bool found = false;
            Console.WriteLine("scanning for packet tracer processes...");

            foreach (var process in Process.GetProcesses())
            {
                if (process.ProcessName != "PacketTracer6" &&
                    process.ProcessName != "PacketTracer7")
                    continue;

                found = true;
                Console.WriteLine("found process: {0} (id: {1})", process.ProcessName, process.Id);

                var ptr = NativeMethods.OpenProcess(0x001F0FFF, true, process.Id);
                if (ptr == IntPtr.Zero)
                {
                    Console.WriteLine("error opening process: {0}", GetWin32Error());
                    continue;
                }

                var version = ReadVersion(ptr);
                if (version == null)
                {
                    NativeMethods.CloseHandle(ptr);
                    Console.WriteLine("error: unsupported packet tracer version");
                    continue;
                }

                Console.WriteLine("packet tracer version: {0}", version.ToString());
                Console.WriteLine("applying patch...");

                try
                {
                    DoMagic(ptr, version);
                }
                catch (Exception e)
                {
                    Console.WriteLine("error patching process: {0}", e);
                }
                finally
                {
                    NativeMethods.CloseHandle(ptr);
                }

                Console.WriteLine("patch successful!");
            }

            if (!found)
            {
                Console.WriteLine("error: no packet tracer processes found");
            }

            Console.WriteLine("press any key to exit...");
            Console.ReadKey();
        }

        static void DoMagic(IntPtr handle, PacketTracer version)
        {
            // replace the instruction at version.Target with a jmp rel32 instruction
            // the goal is to skip all of the checks and warnings related to user profile changes
            unchecked
            {
                // calculate how far we need to jump
                // -5 because the jmp rel32 instruction is 5 bytes long
                uint dist = (uint)version.EndpointPtr.ToInt32() - (uint)version.TargetPtr.ToInt32() - 5u;

                WriteMemory(handle,
                   version.TargetPtr,
                   new byte[] { 0xE9, (byte)dist, (byte)(dist >> 8), (byte)(dist >> 16), (byte)(dist >> 24) }
               );
            }
        }

        static PacketTracer ReadVersion(IntPtr process)
        {
            foreach (var version in _versions)
            {
                try
                {
                    var versionBytes = ReadMemory(process, version.VersionPtr, (uint)version.ToString().Length);
                    if (Encoding.ASCII.GetString(versionBytes) == version.ToString())
                        return version;
                }
                catch { }
            }

            return null;
        }

        static byte[] ReadMemory(IntPtr process, IntPtr address, uint length)
        {
            uint read = 0;
            byte[] buffer = new byte[length];

            if (!NativeMethods.ReadProcessMemory(process, address, buffer, length, ref read))
                throw new Exception(GetWin32Error());

            if (read != length)
                throw new Exception("could not read requested amount of bytes");

            return buffer;
        }

        static void WriteMemory(IntPtr process, IntPtr address, byte[] buffer)
        {
            uint written = 0;
            if (!NativeMethods.WriteProcessMemory(process, address, buffer, (uint)buffer.Length, ref written))
                throw new Exception(GetWin32Error());

            if (written != (uint)buffer.Length)
                throw new Exception("could not write requested amount of bytes");
        }

        static void WriteMemory(IntPtr process, IntPtr address, byte b)
        {
            WriteMemory(process, address, new byte[] { b });
        }

        static string GetWin32Error()
        {
            return string.Format("0x{0:X}", Marshal.GetLastWin32Error());
        }

        static PacketTracer[] _versions =
        {
            new PacketTracer(new IntPtr(0x0281F628), new IntPtr(0x00C78633), new IntPtr(0x00C78880), "6.2.0.0052"),
            new PacketTracer(new IntPtr(0x02D97670), new IntPtr(0x00C823C3), new IntPtr(0x00C82610), "6.3.0.0009"),
            new PacketTracer(new IntPtr(0x02B2984C), new IntPtr(0x00CFC423), new IntPtr(0x00CFC6A9), "7.0.0.0201"),
            new PacketTracer(new IntPtr(0x0309B900), new IntPtr(0x00CFCEB3), new IntPtr(0x00CFD139), "7.0.0.0305"),
            new PacketTracer(new IntPtr(0x01FD0030), new IntPtr(0x016022D2), new IntPtr(0x01602486), "7.1.0.0221"),
            new PacketTracer(new IntPtr(0x01FCEA00), new IntPtr(0x016010D4), new IntPtr(0x01601288), "7.1.1.0137"),
            new PacketTracer(new IntPtr(0x022A9E5C), new IntPtr(0x016F4C70), new IntPtr(0x016F4E27), "7.2.2.0417"),
        };
    }

    static class NativeMethods
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadProcessMemory(IntPtr process, IntPtr address, byte[] buffer, uint size, ref uint read);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(IntPtr process, IntPtr address, byte[] buffer, uint size, ref uint written);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(uint access, bool inheritHandle, int processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr process);
    }

    class PacketTracer
    {
        public readonly IntPtr VersionPtr;
        public readonly IntPtr TargetPtr;
        public readonly IntPtr EndpointPtr;

        private string _version;

        public PacketTracer(IntPtr versionPtr, IntPtr targetPtr, IntPtr endpointPtr, string versionString)
        {
            VersionPtr = versionPtr;
            TargetPtr = targetPtr;
            EndpointPtr = endpointPtr;
            _version = versionString;
        }

        public override string ToString()
        {
            return _version;
        }
    }
}
