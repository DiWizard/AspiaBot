// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: aspia.key.exchange.proto

package info.malenkov.aspiabot.proto;

/**
 * Protobuf enum {@code info.malenkov.aspiabot.proto.Encryption}
 */
public enum Encryption
    implements com.google.protobuf.ProtocolMessageEnum {
  /**
   * <code>ENCRYPTION_UNKNOWN = 0;</code>
   */
  ENCRYPTION_UNKNOWN(0),
  /**
   * <code>ENCRYPTION_CHACHA20_POLY1305 = 1;</code>
   */
  ENCRYPTION_CHACHA20_POLY1305(1),
  /**
   * <code>ENCRYPTION_AES256_GCM = 2;</code>
   */
  ENCRYPTION_AES256_GCM(2),
  UNRECOGNIZED(-1),
  ;

  /**
   * <code>ENCRYPTION_UNKNOWN = 0;</code>
   */
  public static final int ENCRYPTION_UNKNOWN_VALUE = 0;
  /**
   * <code>ENCRYPTION_CHACHA20_POLY1305 = 1;</code>
   */
  public static final int ENCRYPTION_CHACHA20_POLY1305_VALUE = 1;
  /**
   * <code>ENCRYPTION_AES256_GCM = 2;</code>
   */
  public static final int ENCRYPTION_AES256_GCM_VALUE = 2;


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
  public static Encryption valueOf(int value) {
    return forNumber(value);
  }

  /**
   * @param value The numeric wire value of the corresponding enum entry.
   * @return The enum associated with the given numeric wire value.
   */
  public static Encryption forNumber(int value) {
    switch (value) {
      case 0: return ENCRYPTION_UNKNOWN;
      case 1: return ENCRYPTION_CHACHA20_POLY1305;
      case 2: return ENCRYPTION_AES256_GCM;
      default: return null;
    }
  }

  public static com.google.protobuf.Internal.EnumLiteMap<Encryption>
      internalGetValueMap() {
    return internalValueMap;
  }
  private static final com.google.protobuf.Internal.EnumLiteMap<
      Encryption> internalValueMap =
        new com.google.protobuf.Internal.EnumLiteMap<Encryption>() {
          public Encryption findValueByNumber(int number) {
            return Encryption.forNumber(number);
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
    return info.malenkov.aspiabot.proto.AspiaKeyExchange.getDescriptor().getEnumTypes().get(2);
  }

  private static final Encryption[] VALUES = values();

  public static Encryption valueOf(
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

  private Encryption(int value) {
    this.value = value;
  }

  // @@protoc_insertion_point(enum_scope:info.malenkov.aspiabot.proto.Encryption)
}
