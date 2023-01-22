// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: aspia.router.admin.proto

package info.malenkov.aspiabot.proto;

/**
 * Protobuf type {@code info.malenkov.aspiabot.proto.HostSessionData}
 */
public final class HostSessionData extends
    com.google.protobuf.GeneratedMessageV3 implements
    // @@protoc_insertion_point(message_implements:info.malenkov.aspiabot.proto.HostSessionData)
    HostSessionDataOrBuilder {
private static final long serialVersionUID = 0L;
  // Use HostSessionData.newBuilder() to construct.
  private HostSessionData(com.google.protobuf.GeneratedMessageV3.Builder<?> builder) {
    super(builder);
  }
  private HostSessionData() {
    hostId_ = emptyLongList();
  }

  @java.lang.Override
  @SuppressWarnings({"unused"})
  protected java.lang.Object newInstance(
      UnusedPrivateParameter unused) {
    return new HostSessionData();
  }

  @java.lang.Override
  public final com.google.protobuf.UnknownFieldSet
  getUnknownFields() {
    return this.unknownFields;
  }
  private HostSessionData(
      com.google.protobuf.CodedInputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    this();
    if (extensionRegistry == null) {
      throw new java.lang.NullPointerException();
    }
    int mutable_bitField0_ = 0;
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
          case 9: {
            if (!((mutable_bitField0_ & 0x00000001) != 0)) {
              hostId_ = newLongList();
              mutable_bitField0_ |= 0x00000001;
            }
            hostId_.addLong(input.readFixed64());
            break;
          }
          case 10: {
            int length = input.readRawVarint32();
            int limit = input.pushLimit(length);
            if (!((mutable_bitField0_ & 0x00000001) != 0) && input.getBytesUntilLimit() > 0) {
              hostId_ = newLongList();
              mutable_bitField0_ |= 0x00000001;
            }
            while (input.getBytesUntilLimit() > 0) {
              hostId_.addLong(input.readFixed64());
            }
            input.popLimit(limit);
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
      if (((mutable_bitField0_ & 0x00000001) != 0)) {
        hostId_.makeImmutable(); // C
      }
      this.unknownFields = unknownFields.build();
      makeExtensionsImmutable();
    }
  }
  public static final com.google.protobuf.Descriptors.Descriptor
      getDescriptor() {
    return info.malenkov.aspiabot.proto.AspiaRouterAdmin.internal_static_info_malenkov_aspiabot_proto_HostSessionData_descriptor;
  }

  @java.lang.Override
  protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internalGetFieldAccessorTable() {
    return info.malenkov.aspiabot.proto.AspiaRouterAdmin.internal_static_info_malenkov_aspiabot_proto_HostSessionData_fieldAccessorTable
        .ensureFieldAccessorsInitialized(
            info.malenkov.aspiabot.proto.HostSessionData.class, info.malenkov.aspiabot.proto.HostSessionData.Builder.class);
  }

  public static final int HOST_ID_FIELD_NUMBER = 1;
  private com.google.protobuf.Internal.LongList hostId_;
  /**
   * <code>repeated fixed64 host_id = 1;</code>
   * @return A list containing the hostId.
   */
  @java.lang.Override
  public java.util.List<java.lang.Long>
      getHostIdList() {
    return hostId_;
  }
  /**
   * <code>repeated fixed64 host_id = 1;</code>
   * @return The count of hostId.
   */
  public int getHostIdCount() {
    return hostId_.size();
  }
  /**
   * <code>repeated fixed64 host_id = 1;</code>
   * @param index The index of the element to return.
   * @return The hostId at the given index.
   */
  public long getHostId(int index) {
    return hostId_.getLong(index);
  }
  private int hostIdMemoizedSerializedSize = -1;

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
    getSerializedSize();
    if (getHostIdList().size() > 0) {
      output.writeUInt32NoTag(10);
      output.writeUInt32NoTag(hostIdMemoizedSerializedSize);
    }
    for (int i = 0; i < hostId_.size(); i++) {
      output.writeFixed64NoTag(hostId_.getLong(i));
    }
    unknownFields.writeTo(output);
  }

  @java.lang.Override
  public int getSerializedSize() {
    int size = memoizedSize;
    if (size != -1) return size;

    size = 0;
    {
      int dataSize = 0;
      dataSize = 8 * getHostIdList().size();
      size += dataSize;
      if (!getHostIdList().isEmpty()) {
        size += 1;
        size += com.google.protobuf.CodedOutputStream
            .computeInt32SizeNoTag(dataSize);
      }
      hostIdMemoizedSerializedSize = dataSize;
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
    if (!(obj instanceof info.malenkov.aspiabot.proto.HostSessionData)) {
      return super.equals(obj);
    }
    info.malenkov.aspiabot.proto.HostSessionData other = (info.malenkov.aspiabot.proto.HostSessionData) obj;

    if (!getHostIdList()
        .equals(other.getHostIdList())) return false;
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
    if (getHostIdCount() > 0) {
      hash = (37 * hash) + HOST_ID_FIELD_NUMBER;
      hash = (53 * hash) + getHostIdList().hashCode();
    }
    hash = (29 * hash) + unknownFields.hashCode();
    memoizedHashCode = hash;
    return hash;
  }

  public static info.malenkov.aspiabot.proto.HostSessionData parseFrom(
      java.nio.ByteBuffer data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static info.malenkov.aspiabot.proto.HostSessionData parseFrom(
      java.nio.ByteBuffer data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static info.malenkov.aspiabot.proto.HostSessionData parseFrom(
      com.google.protobuf.ByteString data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static info.malenkov.aspiabot.proto.HostSessionData parseFrom(
      com.google.protobuf.ByteString data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static info.malenkov.aspiabot.proto.HostSessionData parseFrom(byte[] data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static info.malenkov.aspiabot.proto.HostSessionData parseFrom(
      byte[] data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static info.malenkov.aspiabot.proto.HostSessionData parseFrom(java.io.InputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input);
  }
  public static info.malenkov.aspiabot.proto.HostSessionData parseFrom(
      java.io.InputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input, extensionRegistry);
  }
  public static info.malenkov.aspiabot.proto.HostSessionData parseDelimitedFrom(java.io.InputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseDelimitedWithIOException(PARSER, input);
  }
  public static info.malenkov.aspiabot.proto.HostSessionData parseDelimitedFrom(
      java.io.InputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseDelimitedWithIOException(PARSER, input, extensionRegistry);
  }
  public static info.malenkov.aspiabot.proto.HostSessionData parseFrom(
      com.google.protobuf.CodedInputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input);
  }
  public static info.malenkov.aspiabot.proto.HostSessionData parseFrom(
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
  public static Builder newBuilder(info.malenkov.aspiabot.proto.HostSessionData prototype) {
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
   * Protobuf type {@code info.malenkov.aspiabot.proto.HostSessionData}
   */
  public static final class Builder extends
      com.google.protobuf.GeneratedMessageV3.Builder<Builder> implements
      // @@protoc_insertion_point(builder_implements:info.malenkov.aspiabot.proto.HostSessionData)
      info.malenkov.aspiabot.proto.HostSessionDataOrBuilder {
    public static final com.google.protobuf.Descriptors.Descriptor
        getDescriptor() {
      return info.malenkov.aspiabot.proto.AspiaRouterAdmin.internal_static_info_malenkov_aspiabot_proto_HostSessionData_descriptor;
    }

    @java.lang.Override
    protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
        internalGetFieldAccessorTable() {
      return info.malenkov.aspiabot.proto.AspiaRouterAdmin.internal_static_info_malenkov_aspiabot_proto_HostSessionData_fieldAccessorTable
          .ensureFieldAccessorsInitialized(
              info.malenkov.aspiabot.proto.HostSessionData.class, info.malenkov.aspiabot.proto.HostSessionData.Builder.class);
    }

    // Construct using info.malenkov.aspiabot.proto.HostSessionData.newBuilder()
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
      hostId_ = emptyLongList();
      bitField0_ = (bitField0_ & ~0x00000001);
      return this;
    }

    @java.lang.Override
    public com.google.protobuf.Descriptors.Descriptor
        getDescriptorForType() {
      return info.malenkov.aspiabot.proto.AspiaRouterAdmin.internal_static_info_malenkov_aspiabot_proto_HostSessionData_descriptor;
    }

    @java.lang.Override
    public info.malenkov.aspiabot.proto.HostSessionData getDefaultInstanceForType() {
      return info.malenkov.aspiabot.proto.HostSessionData.getDefaultInstance();
    }

    @java.lang.Override
    public info.malenkov.aspiabot.proto.HostSessionData build() {
      info.malenkov.aspiabot.proto.HostSessionData result = buildPartial();
      if (!result.isInitialized()) {
        throw newUninitializedMessageException(result);
      }
      return result;
    }

    @java.lang.Override
    public info.malenkov.aspiabot.proto.HostSessionData buildPartial() {
      info.malenkov.aspiabot.proto.HostSessionData result = new info.malenkov.aspiabot.proto.HostSessionData(this);
      int from_bitField0_ = bitField0_;
      if (((bitField0_ & 0x00000001) != 0)) {
        hostId_.makeImmutable();
        bitField0_ = (bitField0_ & ~0x00000001);
      }
      result.hostId_ = hostId_;
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
      if (other instanceof info.malenkov.aspiabot.proto.HostSessionData) {
        return mergeFrom((info.malenkov.aspiabot.proto.HostSessionData)other);
      } else {
        super.mergeFrom(other);
        return this;
      }
    }

    public Builder mergeFrom(info.malenkov.aspiabot.proto.HostSessionData other) {
      if (other == info.malenkov.aspiabot.proto.HostSessionData.getDefaultInstance()) return this;
      if (!other.hostId_.isEmpty()) {
        if (hostId_.isEmpty()) {
          hostId_ = other.hostId_;
          bitField0_ = (bitField0_ & ~0x00000001);
        } else {
          ensureHostIdIsMutable();
          hostId_.addAll(other.hostId_);
        }
        onChanged();
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
      info.malenkov.aspiabot.proto.HostSessionData parsedMessage = null;
      try {
        parsedMessage = PARSER.parsePartialFrom(input, extensionRegistry);
      } catch (com.google.protobuf.InvalidProtocolBufferException e) {
        parsedMessage = (info.malenkov.aspiabot.proto.HostSessionData) e.getUnfinishedMessage();
        throw e.unwrapIOException();
      } finally {
        if (parsedMessage != null) {
          mergeFrom(parsedMessage);
        }
      }
      return this;
    }
    private int bitField0_;

    private com.google.protobuf.Internal.LongList hostId_ = emptyLongList();
    private void ensureHostIdIsMutable() {
      if (!((bitField0_ & 0x00000001) != 0)) {
        hostId_ = mutableCopy(hostId_);
        bitField0_ |= 0x00000001;
       }
    }
    /**
     * <code>repeated fixed64 host_id = 1;</code>
     * @return A list containing the hostId.
     */
    public java.util.List<java.lang.Long>
        getHostIdList() {
      return ((bitField0_ & 0x00000001) != 0) ?
               java.util.Collections.unmodifiableList(hostId_) : hostId_;
    }
    /**
     * <code>repeated fixed64 host_id = 1;</code>
     * @return The count of hostId.
     */
    public int getHostIdCount() {
      return hostId_.size();
    }
    /**
     * <code>repeated fixed64 host_id = 1;</code>
     * @param index The index of the element to return.
     * @return The hostId at the given index.
     */
    public long getHostId(int index) {
      return hostId_.getLong(index);
    }
    /**
     * <code>repeated fixed64 host_id = 1;</code>
     * @param index The index to set the value at.
     * @param value The hostId to set.
     * @return This builder for chaining.
     */
    public Builder setHostId(
        int index, long value) {
      ensureHostIdIsMutable();
      hostId_.setLong(index, value);
      onChanged();
      return this;
    }
    /**
     * <code>repeated fixed64 host_id = 1;</code>
     * @param value The hostId to add.
     * @return This builder for chaining.
     */
    public Builder addHostId(long value) {
      ensureHostIdIsMutable();
      hostId_.addLong(value);
      onChanged();
      return this;
    }
    /**
     * <code>repeated fixed64 host_id = 1;</code>
     * @param values The hostId to add.
     * @return This builder for chaining.
     */
    public Builder addAllHostId(
        java.lang.Iterable<? extends java.lang.Long> values) {
      ensureHostIdIsMutable();
      com.google.protobuf.AbstractMessageLite.Builder.addAll(
          values, hostId_);
      onChanged();
      return this;
    }
    /**
     * <code>repeated fixed64 host_id = 1;</code>
     * @return This builder for chaining.
     */
    public Builder clearHostId() {
      hostId_ = emptyLongList();
      bitField0_ = (bitField0_ & ~0x00000001);
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


    // @@protoc_insertion_point(builder_scope:info.malenkov.aspiabot.proto.HostSessionData)
  }

  // @@protoc_insertion_point(class_scope:info.malenkov.aspiabot.proto.HostSessionData)
  private static final info.malenkov.aspiabot.proto.HostSessionData DEFAULT_INSTANCE;
  static {
    DEFAULT_INSTANCE = new info.malenkov.aspiabot.proto.HostSessionData();
  }

  public static info.malenkov.aspiabot.proto.HostSessionData getDefaultInstance() {
    return DEFAULT_INSTANCE;
  }

  private static final com.google.protobuf.Parser<HostSessionData>
      PARSER = new com.google.protobuf.AbstractParser<HostSessionData>() {
    @java.lang.Override
    public HostSessionData parsePartialFrom(
        com.google.protobuf.CodedInputStream input,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return new HostSessionData(input, extensionRegistry);
    }
  };

  public static com.google.protobuf.Parser<HostSessionData> parser() {
    return PARSER;
  }

  @java.lang.Override
  public com.google.protobuf.Parser<HostSessionData> getParserForType() {
    return PARSER;
  }

  @java.lang.Override
  public info.malenkov.aspiabot.proto.HostSessionData getDefaultInstanceForType() {
    return DEFAULT_INSTANCE;
  }

}
