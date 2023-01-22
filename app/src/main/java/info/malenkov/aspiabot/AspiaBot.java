package info.malenkov.aspiabot;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;

import com.google.protobuf.ByteString;

import info.malenkov.aspiabot.proto.Encryption;
import info.malenkov.aspiabot.proto.HostSessionData;
import info.malenkov.aspiabot.proto.SrpIdentify;
import info.malenkov.aspiabot.proto.ClientHello;
import info.malenkov.aspiabot.proto.Identify;
import info.malenkov.aspiabot.proto.ServerHello;
import info.malenkov.aspiabot.proto.Session;
import info.malenkov.aspiabot.proto.SrpServerKeyExchange;
import info.malenkov.aspiabot.proto.SrpClientKeyExchange;
import info.malenkov.aspiabot.proto.SessionChallenge;
import info.malenkov.aspiabot.proto.SessionList;
import info.malenkov.aspiabot.proto.SessionListRequest;
import info.malenkov.aspiabot.proto.AdminToRouter;
import info.malenkov.aspiabot.proto.RouterSession;
import info.malenkov.aspiabot.proto.RouterToAdmin;
import info.malenkov.aspiabot.proto.SessionResponse;
import info.malenkov.aspiabot.proto.Version;

public class AspiaBot {
	private final static int abMajorVersion = 1;
	private final static int abMinorVesion = 0;
	private final static int abPath = 0;
	private final static int abRevision = 0;

	private static long requestedId = 0;
	private static boolean silent = false;
	private static boolean debug = false;
	private static boolean printJVMInfo = false;
	private static String hosts = null;
	private static String domain = "";
	private static String memo = null;
	private static String aspiaURL = null;
	private static int aspiaPort = 0;
	private static String aspiaUser  = null;
	private static String aspiaPassword  = null;
	private static int socketTimeout = 0;
	
	private static String abName = "AspiaBot";
	private static String abOS = "Java VM";
	private static String abCopyright = "(c) Copyright 2023 Maxim V. Malenkov\n\nThird-party component:\n- guava (c) 2009 Google Inc.; Apache-2.0 license\n- protobuf (c) 2008 Google Inc.; BSD 3-Clause License\n- bouncycastle (c) 2000 - 2021 The Legion of the Bouncy Castle Inc; MIT license";

	
	public static final void run() throws Exception {
		Encryption serverEncryption = Encryption.ENCRYPTION_UNKNOWN;
		SPREngine sprEngine = null;
		boolean alwaysFine = true;
		List<HostInfo> hostInfoList = new ArrayList<HostInfo>();
		byte[] data = null;
		
		if(!silent || debug){
			System.out.println("Connecting to " + aspiaURL + ":" + aspiaPort);
			if(InetAddress.getLocalHost().getHostName().length()>0){
				abName = InetAddress.getLocalHost().getHostName();
			}
			if(printJVMInfo) printFullJVMInfo();
			if(!debug) System.out.println("Please, wait ...");
		}

		try {
			Socket socket = new Socket(aspiaURL, aspiaPort);
			socket.setSoTimeout(socketTimeout);
			BufferedOutputStream out = new BufferedOutputStream(socket.getOutputStream());
			BufferedInputStream in = new BufferedInputStream(socket.getInputStream());

			// ---->>> ClientHello
			ClientHello clientHello = ClientHello.newBuilder()
					.setEncryption(Encryption.ENCRYPTION_CHACHA20_POLY1305_VALUE | Encryption.ENCRYPTION_AES256_GCM_VALUE)
					.setIdentify(Identify.IDENTIFY_SRP)
					.build();
			byte[] clientHelloDATA = addSize(clientHello.toByteArray());
			debugPrintLn("\n--->>> #1 Sent [ClientHello] " + String.valueOf(clientHelloDATA.length) + " bytes: " + SPRMatch.bytesToHex(clientHelloDATA) + "\n");
			out.write(clientHelloDATA);
			out.flush();

			// <<<---- ServerHello
			if(alwaysFine){
				data = read(in);
				if (data.length > 0) {
					debugPrintLn("<<<--- Received " + String.valueOf(data.length) + " bytes: " + SPRMatch.bytesToHex(data));
					data = skipSize(data);
					if (var128Decode(data) > 0) {
						ServerHello serverHello = ServerHello.parseFrom(data);
						serverEncryption = serverHello.getEncryption();
						debugPrintLn("Encryption method: " + serverEncryption);
					}else{
						System.out.print("<!> ServerHello protobuf error.");
						alwaysFine = false;
					}
				}else{
					System.out.print("<!> ServerHello error.");
					alwaysFine = false;
				}
			}

			// ---->>> SrpIdentify
			if(alwaysFine){
				SrpIdentify srpIdentify = SrpIdentify.newBuilder().setUsername(aspiaUser).build();
				byte[] srpIdentifyDATA = addSize(srpIdentify.toByteArray());
				debugPrintLn("\n--->>> #2 Sent [SrpIdentify] " + String.valueOf(srpIdentifyDATA.length) + " bytes: " + SPRMatch.bytesToHex(srpIdentifyDATA) + "\n");
				out.write(srpIdentifyDATA);
				out.flush();
			}

			// <<<---- SrpServerKeyExchange
			if(alwaysFine){
				data = read(in);
				if (data.length > 0) {
					debugPrintLn("<<<--- Received " + String.valueOf(data.length) + " bytes: "	+ SPRMatch.bytesToHex(data));
					if (var128Decode(data) > 0) {
						data = skipSize(data);
						SrpServerKeyExchange srpServerKeyExchange = SrpServerKeyExchange.parseFrom(data);
						debugPrintLn("Srv number  = " + SPRMatch.bytesToHex(srpServerKeyExchange.getNumber().toByteArray()));
						debugPrintLn("Srv gen     = " + SPRMatch.bytesToHex(srpServerKeyExchange.getGenerator().toByteArray()));
						debugPrintLn("Srv salt    = " + SPRMatch.bytesToHex(srpServerKeyExchange.getSalt().toByteArray()));
						debugPrintLn("Srv B       = " + SPRMatch.bytesToHex(srpServerKeyExchange.getB().toByteArray()));
						debugPrintLn("Srv iv      = " + SPRMatch.bytesToHex(srpServerKeyExchange.getIv().toByteArray()));
						sprEngine = new SPREngine(aspiaUser , aspiaPassword, 
							serverEncryption,
							srpServerKeyExchange.getNumber().toByteArray(), 
							srpServerKeyExchange.getGenerator().toByteArray(), 
							srpServerKeyExchange.getSalt().toByteArray(), 
							srpServerKeyExchange.getB().toByteArray(), 
							srpServerKeyExchange.getIv().toByteArray());
						debugPrintLn("String number = \"" + SPRMatch.bytesToHex(srpServerKeyExchange.getNumber().toByteArray()) + "\"");
						debugPrintLn("String gen    = \"" + SPRMatch.bytesToHex(srpServerKeyExchange.getGenerator().toByteArray()) + "\"");
						debugPrintLn("String salt   = \"" + SPRMatch.bytesToHex(srpServerKeyExchange.getSalt().toByteArray()) + "\"");
						debugPrintLn("String B      = \"" + SPRMatch.bytesToHex(srpServerKeyExchange.getB().toByteArray()) + "\"");
						debugPrintLn("String iv     = \"" + SPRMatch.bytesToHex(srpServerKeyExchange.getIv().toByteArray()) + "\"");
					}else{
						System.out.print("<!> SprServerKeyExchange protobuf error.");
						alwaysFine = false;
					}
				}else{
					System.out.print("<!> SprServerKeyExchange error.");
					alwaysFine = false;
				}
			}

			// ---->>> SrpClientKeyExchange
			if(alwaysFine && sprEngine != null){
				SrpClientKeyExchange srpClientKeyExchange = SrpClientKeyExchange.newBuilder()
					.setA(ByteString.copyFrom(sprEngine.getA()))
					.setIv(ByteString.copyFrom(sprEngine.getIV()))
					.build();

				byte[] srpClientKeyExchangeDATA = addSize(srpClientKeyExchange.toByteArray());
				debugPrintLn("\n--->>> Sent #3 [SrpClientKeyExchange] " + String.valueOf(srpClientKeyExchangeDATA.length) + " bytes: " + SPRMatch.bytesToHex(srpClientKeyExchangeDATA) + "\n");
				out.write(srpClientKeyExchangeDATA);
				out.flush();
			}

			// <<<----- SessionChallenge
			if(alwaysFine && sprEngine != null){
				data = read(in);
				if (data.length > 0) {
					debugPrintLn("<<<--- Received " + String.valueOf(data.length) + " bytes: "	+ SPRMatch.bytesToHex(data));
					if (var128Decode(data) > 0) {
						data = skipSize(data);
						debugPrintLn("DATA = " + SPRMatch.bytesToHex(data));
						debugPrintLn("");
						SessionChallenge sessionChallenge = SessionChallenge.parseFrom(sprEngine.decrypt(data));
						Version aspiaVersion = sessionChallenge.getVersion();
						debugPrintLn("Aspia       = " + aspiaVersion.getMajor() + "." + aspiaVersion.getMinor() + "." + aspiaVersion.getPatch() + " " + aspiaVersion.getRevision());
						debugPrintLn("Sessions    = " + sessionChallenge.getSessionTypes());
						debugPrintLn("CPU cores   = " + sessionChallenge.getCpuCores());
						debugPrintLn("OS name     = " + sessionChallenge.getOsName());
						debugPrintLn("Computer name  = " + sessionChallenge.getComputerName());
						if(!((sessionChallenge.getSessionTypes() & RouterSession.ROUTER_SESSION_ADMIN_VALUE) == RouterSession.ROUTER_SESSION_ADMIN_VALUE)){
							System.out.print("<!> Requested ROUTER_SESSION_ADMIN mode is unsupported by host.");
							alwaysFine = false;
						}
					}else{
						System.out.print("<!> SessionChallenge protobuf error.");
						alwaysFine = false;
					}
				}else{
					System.out.print("<!> SessionChallenge error.");
					alwaysFine = false;
				}
			}

			// ---->>> SessionResponse
			if(alwaysFine && sprEngine != null){
				Version aspiaBotVersion = Version.newBuilder().setMajor(abMajorVersion).setMinor(abMinorVesion).setPatch(abPath).setRevision(abRevision).build();
				SessionResponse sessionResponse = SessionResponse.newBuilder().setSessionType(RouterSession.ROUTER_SESSION_ADMIN_VALUE).setVersion(aspiaBotVersion).setCpuCores(1).setOsName(abOS).setComputerName(abName).build();
				byte[] sessionResponseDATA = addSize(sprEngine.encrypt(sessionResponse.toByteArray()));
				debugPrintLn("\n--->>> Sent #4 [SessionResponse] " + String.valueOf(sessionResponseDATA.length) + " bytes: " + SPRMatch.bytesToHex(sessionResponseDATA) + "\n");
				out.write(sessionResponseDATA);
				out.flush();
			}

			// ---->>> AdminToRouter -> SessionListRequest
			if(alwaysFine && sprEngine != null){
				SessionListRequest sessionListRequest = SessionListRequest.newBuilder().setDummy(1).build();
				AdminToRouter adminToRouter_SessionListRequest = AdminToRouter.newBuilder().setSessionListRequest(sessionListRequest).build();
				byte[] adminToRouter_SessionListRequestDATA = addSize(sprEngine.encrypt(adminToRouter_SessionListRequest.toByteArray()));
				debugPrintLn("\n--->>> Sent #5 [AdminToRouter->SessionListRequest] " + String.valueOf(adminToRouter_SessionListRequestDATA.length) + " bytes: " + SPRMatch.bytesToHex(adminToRouter_SessionListRequestDATA) + "\n");
				out.write(adminToRouter_SessionListRequestDATA);
				out.flush();
			}

			// <<<----- RouterToAdmin
			if(alwaysFine && sprEngine != null){	
				data = read(in);
				if (data.length > 0) {
					debugPrintLn("<<<--- Received " + String.valueOf(data.length) + " bytes: "	+ SPRMatch.bytesToHex(data));
					if (var128Decode(data) > 0) {
						data = skipSize(data);
						debugPrintLn("DATA = " + SPRMatch.bytesToHex(data));
						debugPrintLn("");
						RouterToAdmin routerToAdmin = RouterToAdmin.parseFrom(sprEngine.decrypt(data));
						SessionList sessionList = routerToAdmin.getSessionList();
						if(sessionList.getErrorCodeValue() == 0){
							int sessionCount = sessionList.getSessionCount();
							debugPrintLn("SessionCount = " + sessionCount);
							if(requestedId == 0 && hosts == null && !debug){
								System.out.println("");
								System.out.println("+------+-----------------+---------------------+------------------------------+");
								System.out.println("|  ID  |   IP ADDRESS    |      HOST NAME      |     OPERATION SYSTEM         |");
								System.out.println("+------+-----------------+---------------------+------------------------------+");
							}
							for (Session session : sessionList.getSessionList()) {
								HostSessionData hostSessinData = HostSessionData.parseFrom(session.getSessionData());
								if(session.getSessionTypeValue() == RouterSession.ROUTER_SESSION_HOST_VALUE){
									for(int inc=0; inc < hostSessinData.getHostIdCount(); inc++){
										debugPrintLn(session.getSessionId() + "/" + hostSessinData.getHostId(inc) + " \t " + session.getIpAddress() + " \t " + session.getComputerName() + " \t " + session.getOsName());
										if(requestedId == 0 && hosts == null && !debug){
											System.out.println("| " + String.format("%4s", hostSessinData.getHostId(inc))  + " | " + String.format("%15s", session.getIpAddress())  + " | " + String.format("%-19s",session.getComputerName()) + " | " + String.format("%-28s",session.getOsName()) + " | ");
											System.out.println("+------+-----------------+---------------------+------------------------------+");

										}
										hostInfoList.add(new HostInfo(hostSessinData.getHostId(inc), session.getSessionId(), session.getIpAddress(), session.getComputerName(), session.getOsName()));
									}
								}
							}
						}
					}else{
						System.out.print("<!> RouterToAdmin protobuf error.");
						alwaysFine = false;
					}
				}else{
					System.out.print("<!> RouterToAdmin error.");
					alwaysFine = false;
				}
			}

			in.close();
			out.close();
			socket.close();

			int exitCode = 0;

			List<String> buffer = new ArrayList<String>();
			List<String> hostsLinesNew = new ArrayList<String>();
			HashMap<Long,String> hostMemoMap = new HashMap<Long,String>();

			if (hostInfoList.size() > 0) {
				if(hosts!=null){
					if(memo!=null){
						if(memo.indexOf(";") > 0){
							String records[] = memo.split(";");
							for(String record: records){
								if(record.indexOf(":") > 0){
									String tmpRec[] = record.split(":");
									if(tmpRec.length == 2){
										hostMemoMap.put(Long.parseLong(tmpRec[0]), tmpRec[1]);
									}
								}
							}
						}
					}
					boolean uft8File = false;
					Path path = Paths.get(hosts);
					if(Files.exists(path)){
						uft8File = isContain_UTF8_BOM(path);
						if(uft8File){
							buffer = Files.readAllLines(path, StandardCharsets.UTF_8);	
							if(buffer.get(0).length() > 1){
								buffer.set(0,buffer.get(0).substring(1));
							}
						}else{
							buffer = Files.readAllLines(path);	
						}
					}
					for(HostInfo host: hostInfoList){
						boolean idFound = false;
						boolean memoFound = false;
						String dnsName = host.getHostId() + domain + ".aspia.local";
						String dnsNameMemo = null;
						String nowJp = (new SimpleDateFormat("yyyy-MM-dd HH:mm Z")).format(new Date());
						String comment = "Aspia host ID:" + host.getHostId() +"; " + host.getName() + "; " + host.getOs() +"; "+ nowJp +";";
		
						for (int inc=0; inc<buffer.size(); inc++) {
							if(buffer.get(inc).trim().toLowerCase().contains(" " + dnsName.toLowerCase()) || buffer.get(inc).trim().toLowerCase().contains("\t" + dnsName.toLowerCase())){
								idFound = true;
								if (!buffer.get(inc).trim().substring(0, buffer.get(inc).trim().toLowerCase().indexOf(dnsName.toLowerCase())-1).trim().equals(host.getIp())){
									buffer.set(inc, host.getIp() + " " + dnsName + " # " + comment);
								}
							}
							if(hostMemoMap.size() > 0){
								if(hostMemoMap.containsKey(host.getHostId())){
									dnsNameMemo = hostMemoMap.get(host.getHostId()) + domain + ".aspia.local";
									if(buffer.get(inc).trim().toLowerCase().contains(" " + dnsNameMemo.toLowerCase()) || buffer.get(inc).trim().toLowerCase().contains("\t" + dnsNameMemo.toLowerCase())){
										memoFound = true;
										if (!buffer.get(inc).trim().substring(0, buffer.get(inc).trim().toLowerCase().indexOf(dnsNameMemo.toLowerCase())-1).trim().equals(host.getIp())){
											buffer.set(inc, host.getIp() + " " + dnsNameMemo + " # " + comment);
										}
									}
								}
							}
						}

						if(!idFound){
							hostsLinesNew.add(host.getIp() + " " + dnsName + " # " + comment);
						}

						if(!memoFound && dnsNameMemo != null){
							hostsLinesNew.add(host.getIp() + " " + dnsNameMemo + " # " + comment);
						}
					}


					PrintWriter hostFileWriter;

					if(uft8File){
						hostFileWriter = new PrintWriter(hosts, "UTF-8");
						hostFileWriter.write(0xfeff);
					}else{
						hostFileWriter = new PrintWriter(hosts);
					}
					
					for(String string: buffer){
						hostFileWriter.println(string);
					}
					for(String string: hostsLinesNew){
						hostFileWriter.println(string);
					}
					hostFileWriter.close();
				}
			}

			for(HostInfo host: hostInfoList){
				if(requestedId > 0){
					if(host.getHostId() == requestedId){
						System.out.println(host.getIp());
						break;
					}
				}
			}

			System.exit(exitCode);

		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private static byte[] addSize(byte[] value) {
		byte[] newBuffer = null;

		if (value.length > 0) {
			int var128Size = (int) var128Size(value.length);
			newBuffer = new byte[value.length + var128Size];
			System.arraycopy(var128Encode(value.length), 0, newBuffer, 0, var128Size);
			System.arraycopy(value, 0, newBuffer, var128Size, value.length);
		}

		return newBuffer;
	}

	private static byte[] skipSize(byte[] value) {
		byte[] newBuffer = null;

		if (value.length > 0) {
			int msgLen = (int) var128Decode(value);
			newBuffer = new byte[msgLen];
			System.arraycopy(value, var128Size(msgLen), newBuffer, 0, msgLen);
		}

		return newBuffer;
	}

	private static byte[] var128Encode(long x) {
		ByteBuffer bb = ByteBuffer.wrap(new byte[var128Size(x)]);

		while (Long.compareUnsigned(x, 127) > 0) {
			bb.put((byte) (x & 127 | 128));
			x >>>= 7;
		}
		bb.put((byte) (x & 127));

		return bb.array();
	}

	private static long var128Decode(byte[] buffer) {
		ByteBuffer bb = ByteBuffer.wrap(buffer);

		long x = 0;
		int shift = 0;
		long b;
		do {
			b = bb.get() & 0xff;
			x |= (b & 127) << shift;
			shift += 7;
		} while ((b & 128) != 0);
		return x;
	}

	private static int var128Size(long x) {
		int size = 1;
		while (Long.compareUnsigned(x, 127) > 0) {
			size++;
			x >>>= 7;
		}
		return size;
	}

	private static byte[] concatenate(byte[] first, byte[] second, int length){
		byte[] combined = new byte[first.length + length];
		
		if(first.length > 0){
			System.arraycopy(first,0,combined,0,first.length);
		}
		if(second.length > 0){
			System.arraycopy(second,0,combined,first.length,length);
		}
		
		return combined;
	}

	private static byte[] read(BufferedInputStream in) throws IOException, InterruptedException{
		int termLength = 0;
		byte[] buffer = new byte[0];
		byte[] term = new byte[16384];

		do{		
			termLength = in.read(term, 0, 16384);
			buffer = concatenate(buffer, term, termLength);
			Thread.sleep(100);
		}while(in.available() > 0);

		return buffer;
	}

	public static void printFullJVMInfo() throws UnknownHostException{
		System.out.println("");
		// java.version						Java Runtime Environment version, which may be interpreted as a Runtime.Version
		System.out.println("Java Runtime Environment version: " + System.getProperty("java.version"));
		// java.version.date				Java Runtime Environment version date, in ISO-8601 YYYY-MM-DD format, which may be interpreted as a java.time.LocalDate
		System.out.println("Java Runtime Environment version date: " + System.getProperty("java.version.date"));
		// java.vendor						Java Runtime Environment vendor
		System.out.println("Java Runtime Environment vendor: " + System.getProperty("java.vendor"));
		// java.vendor.url					Java vendor URL
		System.out.println("Java vendor URL: " + System.getProperty("java.vendor.url"));
		// java.vendor.version				Java vendor version
		System.out.println("Java vendor version: " + System.getProperty("java.vendor.version"));
		// java.home						Java installation directory
		System.out.println("Java installation directory: " + System.getProperty("java.home"));
		// java.vm.specification.version	Java Virtual Machine specification version, whose value is the feature element of the runtime version
		System.out.println("Java Virtual Machine specification version: " + System.getProperty("java.vm.specification.version"));
		// java.vm.specification.vendor		Java Virtual Machine specification vendor
		System.out.println("Java Virtual Machine specification vendor: " + System.getProperty("java.vm.specification.vendor"));
		// java.vm.specification.name		Java Virtual Machine specification name
		System.out.println("Java Virtual Machine specification name: " + System.getProperty("java.vm.specification.name"));
		// java.vm.version					Java Virtual Machine implementation version which may be interpreted as a Runtime.Version
		System.out.println("Java Virtual Machine implementation version: " + System.getProperty("java.vm.version"));
		// java.vm.vendor					Java Virtual Machine implementation vendor
		System.out.println("Java Virtual Machine implementation vendor: " + System.getProperty("java.vm.vendor"));
		// java.vm.name						Java Virtual Machine implementation name
		System.out.println("Java Virtual Machine implementation name: " + System.getProperty("java.vm.name"));
		// java.specification.version		Java Runtime Environment specification version, whose value is the feature element of the runtime version
		System.out.println("Java Runtime Environment specification version: " + System.getProperty("java.specification.version"));
		// java.specification.vendor		Java Runtime Environment specification vendor
		System.out.println("Java Runtime Environment specification vendor: " + System.getProperty("java.specification.vendor"));
		// java.specification.name			Java Runtime Environment specification name
		System.out.println("Java Runtime Environment specification name: " + System.getProperty("java.specification.name"));
		// java.class.version				Java class format version number
		System.out.println("Java class format version number: " + System.getProperty("java.class.version"));
		// java.class.path					Java class path (refer to ClassLoader.getSystemClassLoader() for details)
		System.out.println("Java class path: " + System.getProperty("java.class.path"));
		// java.library.path				List of paths to search when loading libraries
		System.out.println("List of paths to search when loading libraries: " + System.getProperty("java.library.path"));
		// java.io.tmpdir					Default temp file path
		System.out.println("Default temp file path: " + System.getProperty("java.io.tmpdir"));
		// java.compiler					Name of JIT compiler to use
		System.out.println("Name of JIT compiler to use: " + System.getProperty("java.compiler"));
		// Host name
		System.out.println("Host name: " + InetAddress.getLocalHost().getHostName());
		// os.name							Operating system name
		System.out.println("Operating system name: " + System.getProperty("os.name"));
		// os.arch							Operating system architecture
		System.out.println("Operating system architecture: " + System.getProperty("os.arch"));
		// os.version						Operating system version
		System.out.println("Operating system version: " + System.getProperty("os.version"));
		// file.separator					File separator ("/" on UNIX)
		System.out.println("File separator: " + System.getProperty("file.separator"));
		// path.separator					Path separator (":" on UNIX)
		System.out.println("Path separator: " + System.getProperty("path.separator"));
		// line.separator					Line separator ("\n" on UNIX)
		System.out.println("Line separator: " + System.getProperty("line.separator"));
		// user.name						User's account name
		System.out.println("User's account name: " + System.getProperty("user.name"));
		// user.home						User's home directory
		System.out.println("User's home directory: " + System.getProperty("user.home"));
		// user.dir							User's current working directory
		System.out.println("User's current working directory: " + System.getProperty("user.dir"));
		System.out.println("");
	}

	private static void debugPrintLn(String msg){
		if(debug) System.out.println(msg);
	}

	private static boolean isContain_UTF8_BOM(Path path) {
		boolean result = false;
		byte[] bom = new byte[3];

		try(InputStream is = new FileInputStream(path.toFile())){
			is.read(bom);
			String content = new String(SPRMatch.bytesToHex(bom));
			if ("efbbbf".equalsIgnoreCase(content)) {
				result = true;
			}
		}catch(Exception e){
			// Do nothing
		}

		return result;
	}

	static public void setID(long value){
		requestedId = value;
	}

	static public void setSilent(boolean value){
		silent = value;
	}

	static public void setDebug(boolean value){
		debug = value;
	}
	
	static public void setJVMInfo(boolean value){
		printJVMInfo = value;
	}

	static public void setHosts(String value){
		hosts = value;
	}

	static public void setDomain(String value){
		domain = "." + value;
	}

	static public void setMemo(String value){
		memo = value;
	}

	static public void setAddress(String value){
		aspiaPort = 8060;
		if(value.indexOf(":") > 0){
			String newUrl[] = value.split(":");
			aspiaURL = newUrl[0]; 
			aspiaPort = Integer.valueOf(newUrl[1]); 
		}else{
			aspiaURL = value;
		}
	}

	static public void setUser(String value){
		aspiaUser = value;
	}

	static public void setPassword(String value){
		aspiaPassword = value;
	}

	static public void setTimeout(int value){
		socketTimeout = value * 1000;
	}

	static public void printVersion(){
		System.out.println(abName + " v." + abMajorVersion + "." + abMinorVesion + "." + abRevision);
		System.out.println(abCopyright);
		System.out.println("");
		if(System.getProperty("java.vendor").length() > 0 && System.getProperty("java.version").length() > 0){
			System.out.println("JavaVM version: " + System.getProperty("java.vendor") + " " + System.getProperty("java.version"));
			if(System.getProperty("os.name").length() > 0 && System.getProperty("os.arch").length() > 0){
				System.out.println("Running on " + System.getProperty("os.name") + " (" + System.getProperty("os.arch") + ")");
				abOS = System.getProperty("os.name") + " (" + System.getProperty("os.arch") + "), Java: " + System.getProperty("java.vendor") + " " + System.getProperty("java.version");
			}
		}
	}

	static class HostInfo{
		private long host_id;
		private long session_id;
		private String ip;
		private String name;
		private String os;
		
		public HostInfo(long host_id, long session_id, String ip, String name, String os){
			this.host_id = host_id;
			this.session_id = session_id;
			this.ip = ip;
			this.name = name;
			this.os = os;
		}

		public long getHostId() { return host_id; }
		public long getSessionId() { return session_id; }
		public String getIp() { return ip; }
		public String getName() { return name; }
		public String getOs() { return os; }
	}

}
