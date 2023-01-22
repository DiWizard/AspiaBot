// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: aspia.router.common.proto

package info.malenkov.aspiabot.proto;

/**
 * Protobuf type {@code info.malenkov.aspiabot.proto.RelayKey}
 */
public final class RelayKey extends
    com.google.protobuf.GeneratedMessageV3 implements
    // @@protoc_insertion_point(message_implements:info.malenkov.aspiabot.proto.RelayKey)
    RelayKeyOrBuilder {
private static final long serialVersionUID = 0L;
  // Use RelayKey.newBuilder() to construct.
  private RelayKey(com.google.protobuf.GeneratedMessageV3.Builder<?> builder) {
    super(builder);
  }
  private RelayKey() {
    type_ = 0;
    encryption_ = 0;
    publicKey_ = com.google.protobuf.ByteString.EMPTY;
    iv_ = com.google.protobuf.ByteString.EMPTY;
  }

  @java.lang.Override
  @SuppressWarnings({"unused"})
  protected java.lang.Object newInstance(
      UnusedPrivateParameter unused) {
    return new RelayKey();
  }

  @java.lang.Override
  public final com.google.protobuf.UnknownFieldSet
  getUnknownFields() {
    return this.unknownFields;
  }
  private RelayKey(
      com.google.protobuf.CodedInputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    this();
    if (extensionRegistry == null) {
      throw new java.lang.NullPointerException();
    }
    com.google.protobuf.UnknownFieldSet.Builder unknownFields =
        com.google.protobuf.UnknownFieldSet.newBuilder();
    try {
      boolean done = false;
      while (!done) {
        int tag = input.readTag();
        switch (tag) {
          case 0:
            done = true;
            break;
          case 8: {

            keyId_ = input.readUInt32();
            break;
          }
          case 16: {
            int rawValue = input.readEnum();

            type_ = rawValue;
            break;
          }
          case 24: {
            int rawValue = input.readEnum();

            encryption_ = rawValue;
            break;
          }
          case 34: {

            publicKey_ = input.readBytes();
            break;
          }
          case 42: {

            iv_ = input.readBytes();
            break;
          }
          default: {
            if (!parseUnknownField(
                input, unknownFields, extensionRegistry, tag)) {
              done = true;
            }
            break;
          }
        }
      }
    } catch (com.google.protobuf.InvalidProtocolBufferException e) {
      throw e.setUnfinishedMessage(this);
    } catch (com.google.protobuf.UninitializedMessageException e) {
      throw e.asInvalidProtocolBufferException().setUnfinishedMessage(this);
    } catch (java.io.IOException e) {
      throw new com.google.protobuf.InvalidProtocolBufferException(
          e).setUnfinishedMessage(this);
    } finally {
      this.unknownFields = unknownFields.build();
      makeExtensionsImmutable();
    }
  }
  public static final com.google.protobuf.Descriptors.Descriptor
      getDescriptor() {
    return info.malenkov.aspiabot.proto.AspiaRouterCommon.internal_static_info_malenkov_aspiabot_proto_RelayKey_descriptor;
  }

  @java.lang.Override
  protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internalGetFieldAccessorTable() {
    return info.malenkov.aspiabot.proto.AspiaRouterCommon.internal_static_info_malenkov_aspiabot_proto_RelayKey_fieldAccessorTable
        .ensureFieldAccessorsInitialized(
            info.malenkov.aspiabot.proto.RelayKey.class, info.malenkov.aspiabot.proto.RelayKey.Builder.class);
  }

  /**
   * Protobuf enum {@code info.malenkov.aspiabot.proto.RelayKey.Type}
   */
  public enum Type
      implements com.google.protobuf.ProtocolMessageEnum {
    /**
     * <code>TYPE_UNKNOWN = 0;</code>
     */
    TYPE_UNKNOWN(0),
    /**
     * <code>TYPE_X25519 = 1;</code>
     */
    TYPE_X25519(1),
    UNRECOGNIZED(-1),
    ;

    /**
     * <code>TYPE_UNKNOWN = 0;</code>
     */
    public static final int TYPE_UNKNOWN_VALUE = 0;
    /**
     * <code>TYPE_X25519 = 1;</code>
     */
    public static final int TYPE_X25519_VALUE = 1;


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
    public static Type valueOf(int value) {
      return forNumber(value);
    }

    /**
     * @param value The numeric wire value of the corresponding enum entry.
     * @return The enum associated with the given numeric wire value.
     */
    public static Type forNumber(int value) {
      switch (value) {
        case 0: return TYPE_UNKNOWN;
        case 1: return TYPE_X25519;
        default: return null;
      }
    }

    public static com.google.protobuf.Internal.EnumLiteMap<Type>
        internalGetValueMap() {
      return internalValueMap;
    }
    private static final com.google.protobuf.Internal.EnumLiteMap<
        Type> internalValueMap =
          new com.google.protobuf.Internal.EnumLiteMap<Type>() {
            public Type findValueByNumber(int number) {
              return Type.forNumber(number);
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
      return info.malenkov.aspiabot.proto.RelayKey.getDescriptor().getEnumTypes().get(0);
    }

    private static final Type[] VALUES = values();

    public static Type valueOf(
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

    private Type(int value) {
      this.value = value;
    }

    // @@protoc_insertion_point(enum_scope:info.malenkov.aspiabot.proto.RelayKey.Type)
  }

  /**
   * Protobuf enum {@code info.malenkov.aspiabot.proto.RelayKey.Encryption}
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
      return info.malenkov.aspiabot.proto.RelayKey.getDescriptor().getEnumTypes().get(1);
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

    // @@protoc_insertion_point(enum_scope:info.malenkov.aspiabot.proto.RelayKey.Encryption)
  }

  public static final int KEY_ID_FIELD_NUMBER = 1;
  private int keyId_;
  /**
   * <pre>
   * Unique key identifier in the proxy pool.
   * </pre>
   *
   * <code>uint32 key_id = 1;</code>
   * @return The keyId.
   */
  @java.lang.Override
  public int getKeyId() {
    return keyId_;
  }

  public static final int TYPE_FIELD_NUMBER = 2;
  private int type_;
  /**
   * <pre>
   * Key type.
   * </pre>
   *
   * <code>.info.malenkov.aspiabot.proto.RelayKey.Type type = 2;</code>
   * @return The enum numeric value on the wire for type.
   */
  @java.lang.Override public int getTypeValue() {
    return type_;
  }
  /**
   * <pre>
   * Key type.
   * </pre>
   *
   * <code>.info.malenkov.aspiabot.proto.RelayKey.Type type = 2;</code>
   * @return The type.
   */
  @java.lang.Override public info.malenkov.aspiabot.proto.RelayKey.Type getType() {
    @SuppressWarnings("deprecation")
    info.malenkov.aspiabot.proto.RelayKey.Type result = info.malenkov.aspiabot.proto.RelayKey.Type.valueOf(type_);
    return result == null ? info.malenkov.aspiabot.proto.RelayKey.Type.UNRECOGNIZED : result;
  }

  public static final int ENCRYPTION_FIELD_NUMBER = 3;
  private int encryption_;
  /**
   * <pre>
   * Encryption algorithm.
   * </pre>
   *
   * <code>.info.malenkov.aspiabot.proto.RelayKey.Encryption encryption = 3;</code>
   * @return The enum numeric value on the wire for encryption.
   */
  @java.lang.Override public int getEncryptionValue() {
    return encryption_;
  }
  /**
   * <pre>
   * Encryption algorithm.
   * </pre>
   *
   * <code>.info.malenkov.aspiabot.proto.RelayKey.Encryption encryption = 3;</code>
   * @return The encryption.
   */
  @java.lang.Override public info.malenkov.aspiabot.proto.RelayKey.Encryption getEncryption() {
    @SuppressWarnings("deprecation")
    info.malenkov.aspiabot.proto.RelayKey.Encryption result = info.malenkov.aspiabot.proto.RelayKey.Encryption.valueOf(encryption_);
    return result == null ? info.malenkov.aspiabot.proto.RelayKey.Encryption.UNRECOGNIZED : result;
  }

  public static final int PUBLIC_KEY_FIELD_NUMBER = 4;
  private com.google.protobuf.ByteString publicKey_;
  /**
   * <pre>
   * Public key of the proxy.
   * </pre>
   *
   * <code>bytes public_key = 4;</code>
   * @return The publicKey.
   */
  @java.lang.Override
  public com.google.protobuf.ByteString getPublicKey() {
    return publicKey_;
  }

  public static final int IV_FIELD_NUMBER = 5;
  private com.google.protobuf.ByteString iv_;
  /**
   * <pre>
   * Initialization vector.
   * </pre>
   *
   * <code>bytes iv = 5;</code>
   * @return The iv.
   */
  @java.lang.Override
  public com.google.protobuf.ByteString getIv() {
    return iv_;
  }

  private byte memoizedIsInitialized = -1;
  @java.lang.Override
  public final boolean isInitialized() {
    byte isInitialized = memoizedIsInitialized;
    if (isInitialized == 1) return true;
    if (isInitialized == 0) return false;

    memoizedIsInitialized = 1;
    return true;
  }

  @java.lang.Override
  public void writeTo(com.google.protobuf.CodedOutputStream output)
                      throws java.io.IOException {
    if (keyId_ != 0) {
      output.writeUInt32(1, keyId_);
    }
    if (type_ != info.malenkov.aspiabot.proto.RelayKey.Type.TYPE_UNKNOWN.getNumber()) {
      output.writeEnum(2, type_);
    }
    if (encryption_ != info.malenkov.aspiabot.proto.RelayKey.Encryption.ENCRYPTION_UNKNOWN.getNumber()) {
      output.writeEnum(3, encryption_);
    }
    if (!publicKey_.isEmpty()) {
      output.writeBytes(4, publicKey_);
    }
    if (!iv_.isEmpty()) {
      output.writeBytes(5, iv_);
    }
    unknownFields.writeTo(output);
  }

  @java.lang.Override
  public int getSerializedSize() {
    int size = memoizedSize;
    if (size != -1) return size;

    size = 0;
    if (keyId_ != 0) {
      size += com.google.protobuf.CodedOutputStream
        .computeUInt32Size(1, keyId_);
    }
    if (type_ != info.malenkov.aspiabot.proto.RelayKey.Type.TYPE_UNKNOWN.getNumber()) {
      size += com.google.protobuf.CodedOutputStream
        .computeEnumSize(2, type_);
    }
    if (encryption_ != info.malenkov.aspiabot.proto.RelayKey.Encryption.ENCRYPTION_UNKNOWN.getNumber()) {
      size += com.google.protobuf.CodedOutputStream
        .computeEnumSize(3, encryption_);
    }
    if (!publicKey_.isEmpty()) {
      size += com.google.protobuf.CodedOutputStream
        .computeBytesSize(4, publicKey_);
    }
    if (!iv_.isEmpty()) {
      size += com.google.protobuf.CodedOutputStream
        .computeBytesSize(5, iv_);
    }
    size += unknownFields.getSerializedSize();
    memoizedSize = size;
    return size;
  }

  @java.lang.Override
  public boolean equals(final java.lang.Object obj) {
    if (obj == this) {
     return true;
    }
    if (!(obj instanceof info.malenkov.aspiabot.proto.RelayKey)) {
      return super.equals(obj);
    }
    info.malenkov.aspiabot.proto.RelayKey other = (info.malenkov.aspiabot.proto.RelayKey) obj;

    if (getKeyId()
        != other.getKeyId()) return false;
    if (type_ != other.type_) return false;
    if (encryption_ != other.encryption_) return false;
    if (!getPublicKey()
        .equals(other.getPublicKey())) return false;
    if (!getIv()
        .equals(other.getIv())) return false;
    if (!unknownFields.equals(other.unknownFields)) return false;
    return true;
  }

  @java.lang.Override
  public int hashCode() {
    if (memoizedHashCode != 0) {
      return memoizedHashCode;
    }
    int hash = 41;
    hash = (19 * hash) + getDescriptor().hashCode();
    hash = (37 * hash) + KEY_ID_FIELD_NUMBER;
    hash = (53 * hash) + getKeyId();
    hash = (37 * hash) + TYPE_FIELD_NUMBER;
    hash = (53 * hash) + type_;
    hash = (37 * hash) + ENCRYPTION_FIELD_NUMBER;
    hash = (53 * hash) + encryption_;
    hash = (37 * hash) + PUBLIC_KEY_FIELD_NUMBER;
    hash = (53 * hash) + getPublicKey().hashCode();
    hash = (37 * hash) + IV_FIELD_NUMBER;
    hash = (53 * hash) + getIv().hashCode();
    hash = (29 * hash) + unknownFields.hashCode();
    memoizedHashCode = hash;
    return hash;
  }

  public static info.malenkov.aspiabot.proto.RelayKey parseFrom(
      java.nio.ByteBuffer data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static info.malenkov.aspiabot.proto.RelayKey parseFrom(
      java.nio.ByteBuffer data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static info.malenkov.aspiabot.proto.RelayKey parseFrom(
      com.google.protobuf.ByteString data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static info.malenkov.aspiabot.proto.RelayKey parseFrom(
      com.google.protobuf.ByteString data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static info.malenkov.aspiabot.proto.RelayKey parseFrom(byte[] data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static info.malenkov.aspiabot.proto.RelayKey parseFrom(
      byte[] data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static info.malenkov.aspiabot.proto.RelayKey parseFrom(java.io.InputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input);
  }
  public static info.malenkov.aspiabot.proto.RelayKey parseFrom(
      java.io.InputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input, extensionRegistry);
  }
  public static info.malenkov.aspiabot.proto.RelayKey parseDelimitedFrom(java.io.InputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseDelimitedWithIOException(PARSER, input);
  }
  public static info.malenkov.aspiabot.proto.RelayKey parseDelimitedFrom(
      java.io.InputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseDelimitedWithIOException(PARSER, input, extensionRegistry);
  }
  public static info.malenkov.aspiabot.proto.RelayKey parseFrom(
      com.google.protobuf.CodedInputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input);
  }
  public static info.malenkov.aspiabot.proto.RelayKey parseFrom(
      com.google.protobuf.CodedInputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input, extensionRegistry);
  }

  @java.lang.Override
  public Builder newBuilderForType() { return newBuilder(); }
  public static Builder newBuilder() {
    return DEFAULT_INSTANCE.toBuilder();
  }
  public static Builder newBuilder(info.malenkov.aspiabot.proto.RelayKey prototype) {
    return DEFAULT_INSTANCE.toBuilder().mergeFrom(prototype);
  }
  @java.lang.Override
  public Builder toBuilder() {
    return this == DEFAULT_INSTANCE
        ? new Builder() : new Builder().mergeFrom(this);
  }

  @java.lang.Override
  protected Builder newBuilderForType(
      com.google.protobuf.GeneratedMessageV3.BuilderParent parent) {
    Builder builder = new Builder(parent);
    return builder;
  }
  /**
   * Protobuf type {@code info.malenkov.aspiabot.proto.RelayKey}
   */
  public static final class Builder extends
      com.google.protobuf.GeneratedMessageV3.Builder<Builder> implements
      // @@protoc_insertion_point(builder_implements:info.malenkov.aspiabot.proto.RelayKey)
      info.malenkov.aspiabot.proto.RelayKeyOrBuilder {
    public static final com.google.protobuf.Descriptors.Descriptor
        getDescriptor() {
      return info.malenkov.aspiabot.proto.AspiaRouterCommon.internal_static_info_malenkov_aspiabot_proto_RelayKey_descriptor;
    }

    @java.lang.Override
    protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
        internalGetFieldAccessorTable() {
      return info.malenkov.aspiabot.proto.AspiaRouterCommon.internal_static_info_malenkov_aspiabot_proto_RelayKey_fieldAccessorTable
          .ensureFieldAccessorsInitialized(
              info.malenkov.aspiabot.proto.RelayKey.class, info.malenkov.aspiabot.proto.RelayKey.Builder.class);
    }

    // Construct using info.malenkov.aspiabot.proto.RelayKey.newBuilder()
    private Builder() {
      maybeForceBuilderInitialization();
    }

    private Builder(
        com.google.protobuf.GeneratedMessageV3.BuilderParent parent) {
      super(parent);
      maybeForceBuilderInitialization();
    }
    private void maybeForceBuilderInitialization() {
      if (com.google.protobuf.GeneratedMessageV3
              .alwaysUseFieldBuilders) {
      }
    }
    @java.lang.Override
    public Builder clear() {
      super.clear();
      keyId_ = 0;

      type_ = 0;

      encryption_ = 0;

      publicKey_ = com.google.protobuf.ByteString.EMPTY;

      iv_ = com.google.protobuf.ByteString.EMPTY;

      return this;
    }

    @java.lang.Override
    public com.google.protobuf.Descriptors.Descriptor
        getDescriptorForType() {
      return info.malenkov.aspiabot.proto.AspiaRouterCommon.internal_static_info_malenkov_aspiabot_proto_RelayKey_descriptor;
    }

    @java.lang.Override
    public info.malenkov.aspiabot.proto.RelayKey getDefaultInstanceForType() {
      return info.malenkov.aspiabot.proto.RelayKey.getDefaultInstance();
    }

    @java.lang.Override
    public info.malenkov.aspiabot.proto.RelayKey build() {
      info.malenkov.aspiabot.proto.RelayKey result = buildPartial();
      if (!result.isInitialized()) {
        throw newUninitializedMessageException(result);
      }
      return result;
    }

    @java.lang.Override
    public info.malenkov.aspiabot.proto.RelayKey buildPartial() {
      info.malenkov.aspiabot.proto.RelayKey result = new info.malenkov.aspiabot.proto.RelayKey(this);
      result.keyId_ = keyId_;
      result.type_ = type_;
      result.encryption_ = encryption_;
      result.publicKey_ = publicKey_;
      result.iv_ = iv_;
      onBuilt();
      return result;
    }

    @java.lang.Override
    public Builder clone() {
      return super.clone();
    }
    @java.lang.Override
    public Builder setField(
        com.google.protobuf.Descriptors.FieldDescriptor field,
        java.lang.Object value) {
      return super.setField(field, value);
    }
    @java.lang.Override
    public Builder clearField(
        com.google.protobuf.Descriptors.FieldDescriptor field) {
      return super.clearField(field);
    }
    @java.lang.Override
    public Builder clearOneof(
        com.google.protobuf.Descriptors.OneofDescriptor oneof) {
      return super.clearOneof(oneof);
    }
    @java.lang.Override
    public Builder setRepeatedField(
        com.google.protobuf.Descriptors.FieldDescriptor field,
        int index, java.lang.Object value) {
      return super.setRepeatedField(field, index, value);
    }
    @java.lang.Override
    public Builder addRepeatedField(
        com.google.protobuf.Descriptors.FieldDescriptor field,
        java.lang.Object value) {
      return super.addRepeatedField(field, value);
    }
    @java.lang.Override
    public Builder mergeFrom(com.google.protobuf.Message other) {
      if (other instanceof info.malenkov.aspiabot.proto.RelayKey) {
        return mergeFrom((info.malenkov.aspiabot.proto.RelayKey)other);
      } else {
        super.mergeFrom(other);
        return this;
      }
    }

    public Builder mergeFrom(info.malenkov.aspiabot.proto.RelayKey other) {
      if (other == info.malenkov.aspiabot.proto.RelayKey.getDefaultInstance()) return this;
      if (other.getKeyId() != 0) {
        setKeyId(other.getKeyId());
      }
      if (other.type_ != 0) {
        setTypeValue(other.getTypeValue());
      }
      if (other.encryption_ != 0) {
        setEncryptionValue(other.getEncryptionValue());
      }
      if (other.getPublicKey() != com.google.protobuf.ByteString.EMPTY) {
        setPublicKey(other.getPublicKey());
      }
      if (other.getIv() != com.google.protobuf.ByteString.EMPTY) {
        setIv(other.getIv());
      }
      this.mergeUnknownFields(other.unknownFields);
      onChanged();
      return this;
    }

    @java.lang.Override
    public final boolean isInitialized() {
      return true;
    }

    @java.lang.Override
    public Builder mergeFrom(
        com.google.protobuf.CodedInputStream input,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws java.io.IOException {
      info.malenkov.aspiabot.proto.RelayKey parsedMessage = null;
      try {
        parsedMessage = PARSER.parsePartialFrom(input, extensionRegistry);
      } catch (com.google.protobuf.InvalidProtocolBufferException e) {
        parsedMessage = (info.malenkov.aspiabot.proto.RelayKey) e.getUnfinishedMessage();
        throw e.unwrapIOException();
      } finally {
        if (parsedMessage != null) {
          mergeFrom(parsedMessage);
        }
      }
      return this;
    }

    private int keyId_ ;
    /**
     * <pre>
     * Unique key identifier in the proxy pool.
     * </pre>
     *
     * <code>uint32 key_id = 1;</code>
     * @return The keyId.
     */
    @java.lang.Override
    public int getKeyId() {
      return keyId_;
    }
    /**
     * <pre>
     * Unique key identifier in the proxy pool.
     * </pre>
     *
     * <code>uint32 key_id = 1;</code>
     * @param value The keyId to set.
     * @return This builder for chaining.
     */
    public Builder setKeyId(int value) {
      
      keyId_ = value;
      onChanged();
      return this;
    }
    /**
     * <pre>
     * Unique key identifier in the proxy pool.
     * </pre>
     *
     * <code>uint32 key_id = 1;</code>
     * @return This builder for chaining.
     */
    public Builder clearKeyId() {
      
      keyId_ = 0;
      onChanged();
      return this;
    }

    private int type_ = 0;
    /**
     * <pre>
     * Key type.
     * </pre>
     *
     * <code>.info.malenkov.aspiabot.proto.RelayKey.Type type = 2;</code>
     * @return The enum numeric value on the wire for type.
     */
    @java.lang.Override public int getTypeValue() {
      return type_;
    }
    /**
     * <pre>
     * Key type.
     * </pre>
     *
     * <code>.info.malenkov.aspiabot.proto.RelayKey.Type type = 2;</code>
     * @param value The enum numeric value on the wire for type to set.
     * @return This builder for chaining.
     */
    public Builder setTypeValue(int value) {
      
      type_ = value;
      onChanged();
      return this;
    }
    /**
     * <pre>
     * Key type.
     * </pre>
     *
     * <code>.info.malenkov.aspiabot.proto.RelayKey.Type type = 2;</code>
     * @return The type.
     */
    @java.lang.Override
    public info.malenkov.aspiabot.proto.RelayKey.Type getType() {
      @SuppressWarnings("deprecation")
      info.malenkov.aspiabot.proto.RelayKey.Type result = info.malenkov.aspiabot.proto.RelayKey.Type.valueOf(type_);
      return result == null ? info.malenkov.aspiabot.proto.RelayKey.Type.UNRECOGNIZED : result;
    }
    /**
     * <pre>
     * Key type.
     * </pre>
     *
     * <code>.info.malenkov.aspiabot.proto.RelayKey.Type type = 2;</code>
     * @param value The type to set.
     * @return This builder for chaining.
     */
    public Builder setType(info.malenkov.aspiabot.proto.RelayKey.Type value) {
      if (value == null) {
        throw new NullPointerException();
      }
      
      type_ = value.getNumber();
      onChanged();
      return this;
    }
    /**
     * <pre>
     * Key type.
     * </pre>
     *
     * <code>.info.malenkov.aspiabot.proto.RelayKey.Type type = 2;</code>
     * @return This builder for chaining.
     */
    public Builder clearType() {
      
      type_ = 0;
      onChanged();
      return this;
    }

    private int encryption_ = 0;
    /**
     * <pre>
     * Encryption algorithm.
     * </pre>
     *
     * <code>.info.malenkov.aspiabot.proto.RelayKey.Encryption encryption = 3;</code>
     * @return The enum numeric value on the wire for encryption.
     */
    @java.lang.Override public int getEncryptionValue() {
      return encryption_;
    }
    /**
     * <pre>
     * Encryption algorithm.
     * </pre>
     *
     * <code>.info.malenkov.aspiabot.proto.RelayKey.Encryption encryption = 3;</code>
     * @param value The enum numeric value on the wire for encryption to set.
     * @return This builder for chaining.
     */
    public Builder setEncryptionValue(int value) {
      
      encryption_ = value;
      onChanged();
      return this;
    }
    /**
     * <pre>
     * Encryption algorithm.
     * </pre>
     *
     * <code>.info.malenkov.aspiabot.proto.RelayKey.Encryption encryption = 3;</code>
     * @return The encryption.
     */
    @java.lang.Override
    public info.malenkov.aspiabot.proto.RelayKey.Encryption getEncryption() {
      @SuppressWarnings("deprecation")
      info.malenkov.aspiabot.proto.RelayKey.Encryption result = info.malenkov.aspiabot.proto.RelayKey.Encryption.valueOf(encryption_);
      return result == null ? info.malenkov.aspiabot.proto.RelayKey.Encryption.UNRECOGNIZED : result;
    }
    /**
     * <pre>
     * Encryption algorithm.
     * </pre>
     *
     * <code>.info.malenkov.aspiabot.proto.RelayKey.Encryption encryption = 3;</code>
     * @param value The encryption to set.
     * @return This builder for chaining.
     */
    public Builder setEncryption(info.malenkov.aspiabot.proto.RelayKey.Encryption value) {
      if (value == null) {
        throw new NullPointerException();
      }
      
      encryption_ = value.getNumber();
      onChanged();
      return this;
    }
    /**
     * <pre>
     * Encryption algorithm.
     * </pre>
     *
     * <code>.info.malenkov.aspiabot.proto.RelayKey.Encryption encryption = 3;</code>
     * @return This builder for chaining.
     */
    public Builder clearEncryption() {
      
      encryption_ = 0;
      onChanged();
      return this;
    }

    private com.google.protobuf.ByteString publicKey_ = com.google.protobuf.ByteString.EMPTY;
    /**
     * <pre>
     * Public key of the proxy.
     * </pre>
     *
     * <code>bytes public_key = 4;</code>
     * @return The publicKey.
     */
    @java.lang.Override
    public com.google.protobuf.ByteString getPublicKey() {
      return publicKey_;
    }
    /**
     * <pre>
     * Public key of the proxy.
     * </pre>
     *
     * <code>bytes public_key = 4;</code>
     * @param value The publicKey to set.
     * @return This builder for chaining.
     */
    public Builder setPublicKey(com.google.protobuf.ByteString value) {
      if (value == null) {
    throw new NullPointerException();
  }
  
      publicKey_ = value;
      onChanged();
      return this;
    }
    /**
     * <pre>
     * Public key of the proxy.
     * </pre>
     *
     * <code>bytes public_key = 4;</code>
     * @return This builder for chaining.
     */
    public Builder clearPublicKey() {
      
      publicKey_ = getDefaultInstance().getPublicKey();
      onChanged();
      return this;
    }

    private com.google.protobuf.ByteString iv_ = com.google.protobuf.ByteString.EMPTY;
    /**
     * <pre>
     * Initialization vector.
     * </pre>
     *
     * <code>bytes iv = 5;</code>
     * @return The iv.
     */
    @java.lang.Override
    public com.google.protobuf.ByteString getIv() {
      return iv_;
    }
    /**
     * <pre>
     * Initialization vector.
     * </pre>
     *
     * <code>bytes iv = 5;</code>
     * @param value The iv to set.
     * @return This builder for chaining.
     */
    public Builder setIv(com.google.protobuf.ByteString value) {
      if (value == null) {
    throw new NullPointerException();
  }
  
      iv_ = value;
      onChanged();
      return this;
    }
    /**
     * <pre>
     * Initialization vector.
     * </pre>
     *
     * <code>bytes iv = 5;</code>
     * @return This builder for chaining.
     */
    public Builder clearIv() {
      
      iv_ = getDefaultInstance().getIv();
      onChanged();
      return this;
    }
    @java.lang.Override
    public final Builder setUnknownFields(
        final com.google.protobuf.UnknownFieldSet unknownFields) {
      return super.setUnknownFields(unknownFields);
    }

    @java.lang.Override
    public final Builder mergeUnknownFields(
        final com.google.protobuf.UnknownFieldSet unknownFields) {
      return super.mergeUnknownFields(unknownFields);
    }


    // @@protoc_insertion_point(builder_scope:info.malenkov.aspiabot.proto.RelayKey)
  }

  // @@protoc_insertion_point(class_scope:info.malenkov.aspiabot.proto.RelayKey)
  private static final info.malenkov.aspiabot.proto.RelayKey DEFAULT_INSTANCE;
  static {
    DEFAULT_INSTANCE = new info.malenkov.aspiabot.proto.RelayKey();
  }

  public static info.malenkov.aspiabot.proto.RelayKey getDefaultInstance() {
    return DEFAULT_INSTANCE;
  }

  private static final com.google.protobuf.Parser<RelayKey>
      PARSER = new com.google.protobuf.AbstractParser<RelayKey>() {
    @java.lang.Override
    public RelayKey parsePartialFrom(
        com.google.protobuf.CodedInputStream input,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return new RelayKey(input, extensionRegistry);
    }
  };

  public static com.google.protobuf.Parser<RelayKey> parser() {
    return PARSER;
  }

  @java.lang.Override
  public com.google.protobuf.Parser<RelayKey> getParserForType() {
    return PARSER;
  }

  @java.lang.Override
  public info.malenkov.aspiabot.proto.RelayKey getDefaultInstanceForType() {
    return DEFAULT_INSTANCE;
  }

}

