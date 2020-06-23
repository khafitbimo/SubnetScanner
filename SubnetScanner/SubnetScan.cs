using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Http.Headers;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;

namespace SubnetScanner
{
    public interface ISubnetScan
    {
        List<HostModel> ScanSubnet(string subnet, int timeout);
        HostModel ScanIP(string ipString, int timeout);
    }
    public class SubnetScan : ISubnetScan
    {
        [DllImport("iphlpapi.dll", ExactSpelling = true)]
        private static extern int SendARP(int DestIP, int SrcIP, byte[] pMacAddr, ref uint PhyAddrLen);

        private static uint macAddrLen = (uint)new byte[6].Length;
        private const string separator = "|";
        private static List<string> macList = new List<string>();

        public SubnetScan(string path)
        {
            LoadMacListFromFile(path);
        }

        private static string MacAddresstoString(byte[] macAdrr)
        {
            string macString = BitConverter.ToString(macAdrr);
            return macString.ToUpper();
        }

        public HostModel ScanIP(string ipString, int timeout)
        {
            HostModel retModel = new HostModel();

            Ping myPing;
            PingReply reply;
            IPAddress address;
            byte[] macAddr = new byte[6];

            IPHostEntry host;

            myPing = new Ping();
            reply = myPing.Send(ipString, timeout);

            if (reply.Status == IPStatus.Success)
            {
                try
                {

                    address = IPAddress.Parse(ipString);
                    host = Dns.GetHostEntry(address);

                    retModel.IP_ADDRESS = ipString;
                    retModel.HOSTNAME = host.HostName;
                    retModel.STATUS = "Up";

                    SendARP((int)BitConverter.ToInt32(address.GetAddressBytes(), 0), 0, macAddr, ref macAddrLen);
                    if (MacAddresstoString(macAddr) != "00-00-00-00-00-00")
                    {
                        string macString = MacAddresstoString(macAddr);
                        retModel.MAC_ADDRESS = macString;
                        retModel.INTERFACE = GetDeviceInfoFromMac(macString);

                    }
                }
                catch (Exception)
                {

                }

                return retModel;
            }

            retModel = null;
            return retModel;
        }

        public List<HostModel> ScanSubnet(string subnet,int timeout)
        {
            Ping myPing;
            PingReply reply;
            IPAddress address;
            byte[] macAddr = new byte[6];

            IPHostEntry host;

            List<HostModel> retModelList = new List<HostModel>();

            for (int i = 1; i < 255; i++)
            {
                HostModel model = new HostModel();

                string subnetn = "." + i.ToString();

                myPing = new Ping();
                reply = myPing.Send(subnet + subnetn, timeout);

                if (reply.Status==IPStatus.Success)
                {
                    try
                    {
                        
                        address = IPAddress.Parse(subnet + subnetn);
                        host = Dns.GetHostEntry(address);

                        model.IP_ADDRESS = subnet + subnetn;
                        model.HOSTNAME = host.HostName;
                        model.STATUS = "Up";

                        SendARP((int)BitConverter.ToInt32(address.GetAddressBytes(), 0), 0, macAddr, ref macAddrLen);
                        if (MacAddresstoString(macAddr) != "00-00-00-00-00-00")
                        {
                            string macString = MacAddresstoString(macAddr);
                            model.MAC_ADDRESS = macString;
                            model.INTERFACE = GetDeviceInfoFromMac(macString);
    
                        }
                    }
                    catch (Exception)
                    {

                    }

                    retModelList.Add(model);
                }
            }

            return retModelList;
        }

        private static string GetDeviceInfoFromMac(string macString)
        {
            string pattern = macString.Substring(0, 8) + ".*";

            try
            {
                foreach (var entry in macList)
                {
                    Match found = Regex.Match(entry, pattern);
                    if (found.Success)
                    {
                        return found.Value.Split(separator[0])[1];
                    }
                }
            }
            catch (Exception e)
            {
                return e.ToString();   //TODO
            }
            return "Unknown";
        }


        private bool LoadMacListFromFile(string path)
        {
            macList = new List<string>();

            try
            {
                foreach (var ipAddress in File.ReadAllLines(path))
                    macList.Add(ipAddress.Trim());
            }
            catch (Exception e)
            {

                return false;
            }
            return true;
        }
    }
}
