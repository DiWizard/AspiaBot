// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: aspia.router.admin.proto

package info.malenkov.aspiabot.proto;

public interface UserOrBuilder extends
    // @@protoc_insertion_point(interface_extends:info.malenkov.aspiabot.proto.User)
    com.google.protobuf.MessageOrBuilder {

  /**
   * <code>int64 entry_id = 1;</code>
   * @return The entryId.
   */
  long getEntryId();

  /**
   * <code>string name = 2;</code>
   * @return The name.
   */
  java.lang.String getName();
  /**
   * <code>string name = 2;</code>
   * @return The bytes for name.
   */
  com.google.protobuf.ByteString
      getNameBytes();

  /**
   * <code>string group = 3;</code>
   * @return The group.
   */
  java.lang.String getGroup();
  /**
   * <code>string group = 3;</code>
   * @return The bytes for group.
   */
  com.google.protobuf.ByteString
      getGroupBytes();

  /**
   * <code>bytes salt = 4;</code>
   * @return The salt.
   */
  com.google.protobuf.ByteString getSalt();

  /**
   * <code>bytes verifier = 5;</code>
   * @return The verifier.
   */
  com.google.protobuf.ByteString getVerifier();

  /**
   * <code>uint32 sessions = 6;</code>
   * @return The sessions.
   */
  int getSessions();

  /**
   * <code>uint32 flags = 7;</code>
   * @return The flags.
   */
  int getFlags();
}
