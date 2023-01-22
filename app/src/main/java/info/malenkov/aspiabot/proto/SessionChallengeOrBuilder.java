// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: aspia.key.exchange.proto

package info.malenkov.aspiabot.proto;

public interface SessionChallengeOrBuilder extends
    // @@protoc_insertion_point(interface_extends:info.malenkov.aspiabot.proto.SessionChallenge)
    com.google.protobuf.MessageOrBuilder {

  /**
   * <code>.info.malenkov.aspiabot.proto.Version version = 1;</code>
   * @return Whether the version field is set.
   */
  boolean hasVersion();
  /**
   * <code>.info.malenkov.aspiabot.proto.Version version = 1;</code>
   * @return The version.
   */
  info.malenkov.aspiabot.proto.Version getVersion();
  /**
   * <code>.info.malenkov.aspiabot.proto.Version version = 1;</code>
   */
  info.malenkov.aspiabot.proto.VersionOrBuilder getVersionOrBuilder();

  /**
   * <code>uint32 session_types = 2;</code>
   * @return The sessionTypes.
   */
  int getSessionTypes();

  /**
   * <code>uint32 cpu_cores = 3;</code>
   * @return The cpuCores.
   */
  int getCpuCores();

  /**
   * <code>string os_name = 4;</code>
   * @return The osName.
   */
  java.lang.String getOsName();
  /**
   * <code>string os_name = 4;</code>
   * @return The bytes for osName.
   */
  com.google.protobuf.ByteString
      getOsNameBytes();

  /**
   * <code>string computer_name = 5;</code>
   * @return The computerName.
   */
  java.lang.String getComputerName();
  /**
   * <code>string computer_name = 5;</code>
   * @return The bytes for computerName.
   */
  com.google.protobuf.ByteString
      getComputerNameBytes();
}