// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: aspia.router.admin.proto

package info.malenkov.aspiabot.proto;

/**
 * Protobuf enum {@code info.malenkov.aspiabot.proto.SessionRequestType}
 */
public enum SessionRequestType
    implements com.google.protobuf.ProtocolMessageEnum {
  /**
   * <code>SESSION_REQUEST_UNKNOWN = 0;</code>
   */
  SESSION_REQUEST_UNKNOWN(0),
  /**
   * <code>SESSION_REQUEST_DISCONNECT = 1;</code>
   */
  SESSION_REQUEST_DISCONNECT(1),
  UNRECOGNIZED(-1),
  ;

  /**
   * <code>SESSION_REQUEST_UNKNOWN = 0;</code>
   */
  public static final int SESSION_REQUEST_UNKNOWN_VALUE = 0;
  /**
   * <code>SESSION_REQUEST_DISCONNECT = 1;</code>
   */
  public static final int SESSION_REQUEST_DISCONNECT_VALUE = 1;


  public final int getNumber() {
    if (this == UNRECOGNIZED) {
      throw new java.lang.IllegalArgumentException(
          "Can't get the number of an unknown enum value.");
    }
    return value;
  }

  /**
   * @param value The numeric wire value of the corresponding enum entry.
   * @return The enum associated with the given numeric wire value.
   * @deprecated Use {@link #forNumber(int)} instead.
   */
  @java.lang.Deprecated
  public static SessionRequestType valueOf(int value) {
    return forNumber(value);
  }

  /**
   * @param value The numeric wire value of the corresponding enum entry.
   * @return The enum associated with the given numeric wire value.
   */
  public static SessionRequestType forNumber(int value) {
    switch (value) {
      case 0: return SESSION_REQUEST_UNKNOWN;
      case 1: return SESSION_REQUEST_DISCONNECT;
      default: return null;
    }
  }

  public static com.google.protobuf.Internal.EnumLiteMap<SessionRequestType>
      internalGetValueMap() {
    return internalValueMap;
  }
  private static final com.google.protobuf.Internal.EnumLiteMap<
      SessionRequestType> internalValueMap =
        new com.google.protobuf.Internal.EnumLiteMap<SessionRequestType>() {
          public SessionRequestType findValueByNumber(int number) {
            return SessionRequestType.forNumber(number);
          }
        };

  public final com.google.protobuf.Descriptors.EnumValueDescriptor
      getValueDescriptor() {
    if (this == UNRECOGNIZED) {
      throw new java.lang.IllegalStateException(
          "Can't get the descriptor of an unrecognized enum value.");
    }
    return getDescriptor().getValues().get(ordinal());
  }
  public final com.google.protobuf.Descriptors.EnumDescriptor
      getDescriptorForType() {
    return getDescriptor();
  }
  public static final com.google.protobuf.Descriptors.EnumDescriptor
      getDescriptor() {
    return info.malenkov.aspiabot.proto.AspiaRouterAdmin.getDescriptor().getEnumTypes().get(0);
  }

  private static final SessionRequestType[] VALUES = values();

  public static SessionRequestType valueOf(
      com.google.protobuf.Descriptors.EnumValueDescriptor desc) {
    if (desc.getType() != getDescriptor()) {
      throw new java.lang.IllegalArgumentException(
        "EnumValueDescriptor is not for this type.");
    }
    if (desc.getIndex() == -1) {
      return UNRECOGNIZED;
    }
    return VALUES[desc.getIndex()];
  }

  private final int value;

  private SessionRequestType(int value) {
    this.value = value;
  }

  // @@protoc_insertion_point(enum_scope:info.malenkov.aspiabot.proto.SessionRequestType)
}

