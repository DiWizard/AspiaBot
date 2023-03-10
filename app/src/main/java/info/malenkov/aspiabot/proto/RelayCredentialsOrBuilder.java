// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: aspia.router.common.proto

package info.malenkov.aspiabot.proto;

public interface RelayCredentialsOrBuilder extends
    // @@protoc_insertion_point(interface_extends:info.malenkov.aspiabot.proto.RelayCredentials)
    com.google.protobuf.MessageOrBuilder {

  /**
   * <code>string host = 1;</code>
   * @return The host.
   */
  java.lang.String getHost();
  /**
   * <code>string host = 1;</code>
   * @return The bytes for host.
   */
  com.google.protobuf.ByteString
      getHostBytes();

  /**
   * <code>uint32 port = 2;</code>
   * @return The port.
   */
  int getPort();

  /**
   * <code>.info.malenkov.aspiabot.proto.RelayKey key = 3;</code>
   * @return Whether the key field is set.
   */
  boolean hasKey();
  /**
   * <code>.info.malenkov.aspiabot.proto.RelayKey key = 3;</code>
   * @return The key.
   */
  info.malenkov.aspiabot.proto.RelayKey getKey();
  /**
   * <code>.info.malenkov.aspiabot.proto.RelayKey key = 3;</code>
   */
  info.malenkov.aspiabot.proto.RelayKeyOrBuilder getKeyOrBuilder();

  /**
   * <code>bytes secret = 4;</code>
   * @return The secret.
   */
  com.google.protobuf.ByteString getSecret();
}
