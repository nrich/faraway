
using System;
using System.Collections;
using System.Net;
using System.IO;
using System.Text;


namespace Faraway
{	
	public class Client
	{
		string hostname;
		UInt16 port;
		bool use_ssl;
		
		public Client(string hostname, UInt16 port, bool use_ssl)
		{
			this.hostname = hostname;
			this.port = port;
			this.use_ssl = use_ssl;
		}
		public Client() : this("localhost", 9095, false)
		{	
		}
		public Client(string host) : this(host, 9095, false)
		{	
		}
		public Client(UInt16 port) : this("localhost", port, false)
		{	
		}
		
		public Hashtable CallRemote(string action, Hashtable args) 
		{
			Hashtable h = new Hashtable();
			h["data"] = args;
			h["timestamp"] = (DateTime.Now.ToUniversalTime().Ticks - 621355968000000000) / 10000000;
			h["checksum"] = 1;
			
			string json = JSON.JsonEncode(h);
			
			HttpWebRequest req = (HttpWebRequest)WebRequest.Create(string.Format("{0}://{1}:{2}/{3}", this.use_ssl ? "https" : "http", this.hostname, this.port, action));
			req.Method = "POST";
			req.ContentLength = json.Length;
			req.ContentType = "application/x-www-form-urlencoded";
			
			Stream stream = req.GetRequestStream();
			stream.Write(ASCIIEncoding.UTF8.GetBytes(json), 0, json.Length);
			stream.Close();
			
			WebResponse res = req.GetResponse();
			
			Stream data = res.GetResponseStream();
			byte[] buffer = new byte[(int)res.ContentLength];
			data.Read(buffer, 0, (int)res.ContentLength);
			
			string jsonstr = ASCIIEncoding.UTF8.GetString(buffer);
			
			return (Hashtable)JSON.JsonDecode(jsonstr);
		}
		
		public Hashtable CallRemote(string action) 
		{
			return CallRemote(action, new Hashtable());	
		}
	}
}
