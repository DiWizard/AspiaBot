// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: aspia.router.admin.proto

package info.malenkov.aspiabot.proto;

public interface UserRequestOrBuilder extends
    // @@protoc_insertion_point(interface_extends:info.malenkov.aspiabot.proto.UserRequest)
    com.google.protobuf.MessageOrBuilder {

  /**
   * <code>.info.malenkov.aspiabot.proto.UserRequestType type = 1;</code>
   * @return The enum numeric value on the wire for type.
   */
  int getTypeValue();
  /**
   * <code>.info.malenkov.aspiabot.proto.UserRequestType type = 1;</code>
   * @return The type.
   */
  info.malenkov.aspiabot.proto.UserRequestType getType();

  /**
   * <code>.info.malenkov.aspiabot.proto.User user = 2;</code>
   * @return Whether the user field is set.
   */
  boolean hasUser();
  /**
   * <code>.info.malenkov.aspiabot.proto.User user = 2;</code>
   * @return The user.
   */
  info.malenkov.aspiabot.proto.User getUser();
  /**
   * <code>.info.malenkov.aspiabot.proto.User user = 2;</code>
   */
  info.malenkov.aspiabot.proto.UserOrBuilder getUserOrBuilder();
}