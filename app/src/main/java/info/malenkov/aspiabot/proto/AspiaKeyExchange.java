// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: aspia.key.exchange.proto

package info.malenkov.aspiabot.proto;

public final class AspiaKeyExchange {
  private AspiaKeyExchange() {}
  public static void registerAllExtensions(
      com.google.protobuf.ExtensionRegistryLite registry) {
  }

  public static void registerAllExtensions(
      com.google.protobuf.ExtensionRegistry registry) {
    registerAllExtensions(
        (com.google.protobuf.ExtensionRegistryLite) registry);
  }
  static final com.google.protobuf.Descriptors.Descriptor
    internal_static_info_malenkov_aspiabot_proto_Version_descriptor;
  static final 
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_info_malenkov_aspiabot_proto_Version_fieldAccessorTable;
  static final com.google.protobuf.Descriptors.Descriptor
    internal_static_info_malenkov_aspiabot_proto_ClientHello_descriptor;
  static final 
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_info_malenkov_aspiabot_proto_ClientHello_fieldAccessorTable;
  static final com.google.protobuf.Descriptors.Descriptor
    internal_static_info_malenkov_aspiabot_proto_ServerHello_descriptor;
  static final 
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_info_malenkov_aspiabot_proto_ServerHello_fieldAccessorTable;
  static final com.google.protobuf.Descriptors.Descriptor
    internal_static_info_malenkov_aspiabot_proto_SrpIdentify_descriptor;
  static final 
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_info_malenkov_aspiabot_proto_SrpIdentify_fieldAccessorTable;
  static final com.google.protobuf.Descriptors.Descriptor
    internal_static_info_malenkov_aspiabot_proto_SrpServerKeyExchange_descriptor;
  static final 
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_info_malenkov_aspiabot_proto_SrpServerKeyExchange_fieldAccessorTable;
  static final com.google.protobuf.Descriptors.Descriptor
    internal_static_info_malenkov_aspiabot_proto_SrpClientKeyExchange_descriptor;
  static final 
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_info_malenkov_aspiabot_proto_SrpClientKeyExchange_fieldAccessorTable;
  static final com.google.protobuf.Descriptors.Descriptor
    internal_static_info_malenkov_aspiabot_proto_SessionChallenge_descriptor;
  static final 
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_info_malenkov_aspiabot_proto_SessionChallenge_fieldAccessorTable;
  static final com.google.protobuf.Descriptors.Descriptor
    internal_static_info_malenkov_aspiabot_proto_SessionResponse_descriptor;
  static final 
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_info_malenkov_aspiabot_proto_SessionResponse_fieldAccessorTable;

  public static com.google.protobuf.Descriptors.FileDescriptor
      getDescriptor() {
    return descriptor;
  }
  private static  com.google.protobuf.Descriptors.FileDescriptor
      descriptor;
  static {
    java.lang.String[] descriptorData = {
      "\n\030aspia.key.exchange.proto\022\034info.malenko" +
      "v.aspiabot.proto\"H\n\007Version\022\r\n\005major\030\001 \001" +
      "(\r\022\r\n\005minor\030\002 \001(\r\022\r\n\005patch\030\003 \001(\r\022\020\n\010revi" +
      "sion\030\004 \001(\r\"{\n\013ClientHello\022\022\n\nencryption\030" +
      "\001 \001(\r\0228\n\010identify\030\002 \001(\0162&.info.malenkov." +
      "aspiabot.proto.Identify\022\022\n\npublic_key\030\003 " +
      "\001(\014\022\n\n\002iv\030\004 \001(\014\"W\n\013ServerHello\022<\n\nencryp" +
      "tion\030\001 \001(\0162(.info.malenkov.aspiabot.prot" +
      "o.Encryption\022\n\n\002iv\030\002 \001(\014\"\037\n\013SrpIdentify\022" +
      "\020\n\010username\030\001 \001(\t\"^\n\024SrpServerKeyExchang" +
      "e\022\016\n\006number\030\001 \001(\014\022\021\n\tgenerator\030\002 \001(\014\022\014\n\004" +
      "salt\030\003 \001(\014\022\t\n\001B\030\004 \001(\014\022\n\n\002iv\030\005 \001(\014\"-\n\024Srp" +
      "ClientKeyExchange\022\t\n\001A\030\001 \001(\014\022\n\n\002iv\030\002 \001(\014" +
      "\"\234\001\n\020SessionChallenge\0226\n\007version\030\001 \001(\0132%" +
      ".info.malenkov.aspiabot.proto.Version\022\025\n" +
      "\rsession_types\030\002 \001(\r\022\021\n\tcpu_cores\030\003 \001(\r\022" +
      "\017\n\007os_name\030\004 \001(\t\022\025\n\rcomputer_name\030\005 \001(\t\"" +
      "\232\001\n\017SessionResponse\0226\n\007version\030\001 \001(\0132%.i" +
      "nfo.malenkov.aspiabot.proto.Version\022\024\n\014s" +
      "ession_type\030\002 \001(\r\022\021\n\tcpu_cores\030\003 \001(\r\022\017\n\007" +
      "os_name\030\004 \001(\t\022\025\n\rcomputer_name\030\005 \001(\t*\327\001\n" +
      "\013SessionType\022\030\n\024SESSION_TYPE_UNKNOWN\020\000\022\037" +
      "\n\033SESSION_TYPE_DESKTOP_MANAGE\020\001\022\035\n\031SESSI" +
      "ON_TYPE_DESKTOP_VIEW\020\002\022\036\n\032SESSION_TYPE_F" +
      "ILE_TRANSFER\020\004\022\034\n\030SESSION_TYPE_SYSTEM_IN" +
      "FO\020\010\022\032\n\026SESSION_TYPE_TEXT_CHAT\020\020\022\024\n\020SESS" +
      "ION_TYPE_ALL\020\037*4\n\010Identify\022\020\n\014IDENTIFY_S" +
      "RP\020\000\022\026\n\022IDENTIFY_ANONYMOUS\020\001*a\n\nEncrypti" +
      "on\022\026\n\022ENCRYPTION_UNKNOWN\020\000\022 \n\034ENCRYPTION" +
      "_CHACHA20_POLY1305\020\001\022\031\n\025ENCRYPTION_AES25" +
      "6_GCM\020\002B\002P\001b\006proto3"
    };
    descriptor = com.google.protobuf.Descriptors.FileDescriptor
      .internalBuildGeneratedFileFrom(descriptorData,
        new com.google.protobuf.Descriptors.FileDescriptor[] {
        });
    internal_static_info_malenkov_aspiabot_proto_Version_descriptor =
      getDescriptor().getMessageTypes().get(0);
    internal_static_info_malenkov_aspiabot_proto_Version_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_info_malenkov_aspiabot_proto_Version_descriptor,
        new java.lang.String[] { "Major", "Minor", "Patch", "Revision", });
    internal_static_info_malenkov_aspiabot_proto_ClientHello_descriptor =
      getDescriptor().getMessageTypes().get(1);
    internal_static_info_malenkov_aspiabot_proto_ClientHello_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_info_malenkov_aspiabot_proto_ClientHello_descriptor,
        new java.lang.String[] { "Encryption", "Identify", "PublicKey", "Iv", });
    internal_static_info_malenkov_aspiabot_proto_ServerHello_descriptor =
      getDescriptor().getMessageTypes().get(2);
    internal_static_info_malenkov_aspiabot_proto_ServerHello_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_info_malenkov_aspiabot_proto_ServerHello_descriptor,
        new java.lang.String[] { "Encryption", "Iv", });
    internal_static_info_malenkov_aspiabot_proto_SrpIdentify_descriptor =
      getDescriptor().getMessageTypes().get(3);
    internal_static_info_malenkov_aspiabot_proto_SrpIdentify_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_info_malenkov_aspiabot_proto_SrpIdentify_descriptor,
        new java.lang.String[] { "Username", });
    internal_static_info_malenkov_aspiabot_proto_SrpServerKeyExchange_descriptor =
      getDescriptor().getMessageTypes().get(4);
    internal_static_info_malenkov_aspiabot_proto_SrpServerKeyExchange_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_info_malenkov_aspiabot_proto_SrpServerKeyExchange_descriptor,
        new java.lang.String[] { "Number", "Generator", "Salt", "B", "Iv", });
    internal_static_info_malenkov_aspiabot_proto_SrpClientKeyExchange_descriptor =
      getDescriptor().getMessageTypes().get(5);
    internal_static_info_malenkov_aspiabot_proto_SrpClientKeyExchange_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_info_malenkov_aspiabot_proto_SrpClientKeyExchange_descriptor,
        new java.lang.String[] { "A", "Iv", });
    internal_static_info_malenkov_aspiabot_proto_SessionChallenge_descriptor =
      getDescriptor().getMessageTypes().get(6);
    internal_static_info_malenkov_aspiabot_proto_SessionChallenge_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_info_malenkov_aspiabot_proto_SessionChallenge_descriptor,
        new java.lang.String[] { "Version", "SessionTypes", "CpuCores", "OsName", "ComputerName", });
    internal_static_info_malenkov_aspiabot_proto_SessionResponse_descriptor =
      getDescriptor().getMessageTypes().get(7);
    internal_static_info_malenkov_aspiabot_proto_SessionResponse_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_info_malenkov_aspiabot_proto_SessionResponse_descriptor,
        new java.lang.String[] { "Version", "SessionType", "CpuCores", "OsName", "ComputerName", });
  }

  // @@protoc_insertion_point(outer_class_scope)
}
