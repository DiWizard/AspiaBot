// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: aspia.key.exchange.proto

package info.malenkov.aspiabot.proto;

public interface ServerHelloOrBuilder extends
    // @@protoc_insertion_point(interface_extends:info.malenkov.aspiabot.proto.ServerHello)
    com.google.protobuf.MessageOrBuilder {

  /**
   * <code>.info.malenkov.aspiabot.proto.Encryption encryption = 1;</code>
   * @return The enum numeric value on the wire for encryption.
   */
  int getEncryptionValue();
  /**
   * <code>.info.malenkov.aspiabot.proto.Encryption encryption = 1;</code>
   * @return The encryption.
   */
  info.malenkov.aspiabot.proto.Encryption getEncryption();

  /**
   * <code>bytes iv = 2;</code>
   * @return The iv.
   */
  com.google.protobuf.ByteString getIv();
}