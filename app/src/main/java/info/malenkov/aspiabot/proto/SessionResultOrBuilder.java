// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: aspia.router.admin.proto

package info.malenkov.aspiabot.proto;

public interface SessionResultOrBuilder extends
    // @@protoc_insertion_point(interface_extends:info.malenkov.aspiabot.proto.SessionResult)
    com.google.protobuf.MessageOrBuilder {

  /**
   * <code>.info.malenkov.aspiabot.proto.SessionRequestType type = 1;</code>
   * @return The enum numeric value on the wire for type.
   */
  int getTypeValue();
  /**
   * <code>.info.malenkov.aspiabot.proto.SessionRequestType type = 1;</code>
   * @return The type.
   */
  info.malenkov.aspiabot.proto.SessionRequestType getType();

  /**
   * <code>.info.malenkov.aspiabot.proto.SessionResult.ErrorCode error_code = 2;</code>
   * @return The enum numeric value on the wire for errorCode.
   */
  int getErrorCodeValue();
  /**
   * <code>.info.malenkov.aspiabot.proto.SessionResult.ErrorCode error_code = 2;</code>
   * @return The errorCode.
   */
  info.malenkov.aspiabot.proto.SessionResult.ErrorCode getErrorCode();
}
