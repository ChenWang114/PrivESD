// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: bigint.proto

#define INTERNAL_SUPPRESS_PROTOBUF_FIELD_DEPRECATION
#include "bigint.pb.h"

#include <algorithm>

#include <google/protobuf/stubs/common.h>
#include <google/protobuf/stubs/once.h>
#include <google/protobuf/io/coded_stream.h>
#include <google/protobuf/wire_format_lite_inl.h>
#include <google/protobuf/descriptor.h>
#include <google/protobuf/generated_message_reflection.h>
#include <google/protobuf/reflection_ops.h>
#include <google/protobuf/wire_format.h>
// @@protoc_insertion_point(includes)

namespace Protobuf {

namespace {

const ::google::protobuf::Descriptor* BigInt_descriptor_ = NULL;
const ::google::protobuf::internal::GeneratedMessageReflection*
  BigInt_reflection_ = NULL;
const ::google::protobuf::Descriptor* BigIntArray_descriptor_ = NULL;
const ::google::protobuf::internal::GeneratedMessageReflection*
  BigIntArray_reflection_ = NULL;
const ::google::protobuf::Descriptor* BigIntMatrix_descriptor_ = NULL;
const ::google::protobuf::internal::GeneratedMessageReflection*
  BigIntMatrix_reflection_ = NULL;
const ::google::protobuf::Descriptor* BigIntMatrix_Collection_descriptor_ = NULL;
const ::google::protobuf::internal::GeneratedMessageReflection*
  BigIntMatrix_Collection_reflection_ = NULL;

}  // namespace


void protobuf_AssignDesc_bigint_2eproto() {
  protobuf_AddDesc_bigint_2eproto();
  const ::google::protobuf::FileDescriptor* file =
    ::google::protobuf::DescriptorPool::generated_pool()->FindFileByName(
      "bigint.proto");
  GOOGLE_CHECK(file != NULL);
  BigInt_descriptor_ = file->message_type(0);
  static const int BigInt_offsets_[1] = {
    GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(BigInt, data_),
  };
  BigInt_reflection_ =
    new ::google::protobuf::internal::GeneratedMessageReflection(
      BigInt_descriptor_,
      BigInt::default_instance_,
      BigInt_offsets_,
      GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(BigInt, _has_bits_[0]),
      GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(BigInt, _unknown_fields_),
      -1,
      ::google::protobuf::DescriptorPool::generated_pool(),
      ::google::protobuf::MessageFactory::generated_factory(),
      sizeof(BigInt));
  BigIntArray_descriptor_ = file->message_type(1);
  static const int BigIntArray_offsets_[1] = {
    GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(BigIntArray, values_),
  };
  BigIntArray_reflection_ =
    new ::google::protobuf::internal::GeneratedMessageReflection(
      BigIntArray_descriptor_,
      BigIntArray::default_instance_,
      BigIntArray_offsets_,
      GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(BigIntArray, _has_bits_[0]),
      GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(BigIntArray, _unknown_fields_),
      -1,
      ::google::protobuf::DescriptorPool::generated_pool(),
      ::google::protobuf::MessageFactory::generated_factory(),
      sizeof(BigIntArray));
  BigIntMatrix_descriptor_ = file->message_type(2);
  static const int BigIntMatrix_offsets_[1] = {
    GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(BigIntMatrix, lines_),
  };
  BigIntMatrix_reflection_ =
    new ::google::protobuf::internal::GeneratedMessageReflection(
      BigIntMatrix_descriptor_,
      BigIntMatrix::default_instance_,
      BigIntMatrix_offsets_,
      GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(BigIntMatrix, _has_bits_[0]),
      GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(BigIntMatrix, _unknown_fields_),
      -1,
      ::google::protobuf::DescriptorPool::generated_pool(),
      ::google::protobuf::MessageFactory::generated_factory(),
      sizeof(BigIntMatrix));
  BigIntMatrix_Collection_descriptor_ = file->message_type(3);
  static const int BigIntMatrix_Collection_offsets_[1] = {
    GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(BigIntMatrix_Collection, matrices_),
  };
  BigIntMatrix_Collection_reflection_ =
    new ::google::protobuf::internal::GeneratedMessageReflection(
      BigIntMatrix_Collection_descriptor_,
      BigIntMatrix_Collection::default_instance_,
      BigIntMatrix_Collection_offsets_,
      GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(BigIntMatrix_Collection, _has_bits_[0]),
      GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(BigIntMatrix_Collection, _unknown_fields_),
      -1,
      ::google::protobuf::DescriptorPool::generated_pool(),
      ::google::protobuf::MessageFactory::generated_factory(),
      sizeof(BigIntMatrix_Collection));
}

namespace {

GOOGLE_PROTOBUF_DECLARE_ONCE(protobuf_AssignDescriptors_once_);
inline void protobuf_AssignDescriptorsOnce() {
  ::google::protobuf::GoogleOnceInit(&protobuf_AssignDescriptors_once_,
                 &protobuf_AssignDesc_bigint_2eproto);
}

void protobuf_RegisterTypes(const ::std::string&) {
  protobuf_AssignDescriptorsOnce();
  ::google::protobuf::MessageFactory::InternalRegisterGeneratedMessage(
    BigInt_descriptor_, &BigInt::default_instance());
  ::google::protobuf::MessageFactory::InternalRegisterGeneratedMessage(
    BigIntArray_descriptor_, &BigIntArray::default_instance());
  ::google::protobuf::MessageFactory::InternalRegisterGeneratedMessage(
    BigIntMatrix_descriptor_, &BigIntMatrix::default_instance());
  ::google::protobuf::MessageFactory::InternalRegisterGeneratedMessage(
    BigIntMatrix_Collection_descriptor_, &BigIntMatrix_Collection::default_instance());
}

}  // namespace

void protobuf_ShutdownFile_bigint_2eproto() {
  delete BigInt::default_instance_;
  delete BigInt_reflection_;
  delete BigIntArray::default_instance_;
  delete BigIntArray_reflection_;
  delete BigIntMatrix::default_instance_;
  delete BigIntMatrix_reflection_;
  delete BigIntMatrix_Collection::default_instance_;
  delete BigIntMatrix_Collection_reflection_;
}

void protobuf_AddDesc_bigint_2eproto() {
  static bool already_here = false;
  if (already_here) return;
  already_here = true;
  GOOGLE_PROTOBUF_VERIFY_VERSION;

  ::google::protobuf::DescriptorPool::InternalAddGeneratedFile(
    "\n\014bigint.proto\022\010Protobuf\"\026\n\006BigInt\022\014\n\004da"
    "ta\030\001 \002(\014\"/\n\013BigIntArray\022 \n\006values\030\001 \003(\0132"
    "\020.Protobuf.BigInt\"4\n\014BigIntMatrix\022$\n\005lin"
    "es\030\001 \003(\0132\025.Protobuf.BigIntArray\"C\n\027BigIn"
    "tMatrix_Collection\022(\n\010matrices\030\001 \003(\0132\026.P"
    "rotobuf.BigIntMatrix", 220);
  ::google::protobuf::MessageFactory::InternalRegisterGeneratedFile(
    "bigint.proto", &protobuf_RegisterTypes);
  BigInt::default_instance_ = new BigInt();
  BigIntArray::default_instance_ = new BigIntArray();
  BigIntMatrix::default_instance_ = new BigIntMatrix();
  BigIntMatrix_Collection::default_instance_ = new BigIntMatrix_Collection();
  BigInt::default_instance_->InitAsDefaultInstance();
  BigIntArray::default_instance_->InitAsDefaultInstance();
  BigIntMatrix::default_instance_->InitAsDefaultInstance();
  BigIntMatrix_Collection::default_instance_->InitAsDefaultInstance();
  ::google::protobuf::internal::OnShutdown(&protobuf_ShutdownFile_bigint_2eproto);
}

// Force AddDescriptors() to be called at static initialization time.
struct StaticDescriptorInitializer_bigint_2eproto {
  StaticDescriptorInitializer_bigint_2eproto() {
    protobuf_AddDesc_bigint_2eproto();
  }
} static_descriptor_initializer_bigint_2eproto_;

// ===================================================================

#ifndef _MSC_VER
const int BigInt::kDataFieldNumber;
#endif  // !_MSC_VER

BigInt::BigInt()
  : ::google::protobuf::Message() {
  SharedCtor();
  // @@protoc_insertion_point(constructor:Protobuf.BigInt)
}

void BigInt::InitAsDefaultInstance() {
}

BigInt::BigInt(const BigInt& from)
  : ::google::protobuf::Message() {
  SharedCtor();
  MergeFrom(from);
  // @@protoc_insertion_point(copy_constructor:Protobuf.BigInt)
}

void BigInt::SharedCtor() {
  ::google::protobuf::internal::GetEmptyString();
  _cached_size_ = 0;
  data_ = const_cast< ::std::string*>(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
  ::memset(_has_bits_, 0, sizeof(_has_bits_));
}

BigInt::~BigInt() {
  // @@protoc_insertion_point(destructor:Protobuf.BigInt)
  SharedDtor();
}

void BigInt::SharedDtor() {
  if (data_ != &::google::protobuf::internal::GetEmptyStringAlreadyInited()) {
    delete data_;
  }
  if (this != default_instance_) {
  }
}

void BigInt::SetCachedSize(int size) const {
  GOOGLE_SAFE_CONCURRENT_WRITES_BEGIN();
  _cached_size_ = size;
  GOOGLE_SAFE_CONCURRENT_WRITES_END();
}
const ::google::protobuf::Descriptor* BigInt::descriptor() {
  protobuf_AssignDescriptorsOnce();
  return BigInt_descriptor_;
}

const BigInt& BigInt::default_instance() {
  if (default_instance_ == NULL) protobuf_AddDesc_bigint_2eproto();
  return *default_instance_;
}

BigInt* BigInt::default_instance_ = NULL;

BigInt* BigInt::New() const {
  return new BigInt;
}

void BigInt::Clear() {
  if (has_data()) {
    if (data_ != &::google::protobuf::internal::GetEmptyStringAlreadyInited()) {
      data_->clear();
    }
  }
  ::memset(_has_bits_, 0, sizeof(_has_bits_));
  mutable_unknown_fields()->Clear();
}

bool BigInt::MergePartialFromCodedStream(
    ::google::protobuf::io::CodedInputStream* input) {
#define DO_(EXPRESSION) if (!(EXPRESSION)) goto failure
  ::google::protobuf::uint32 tag;
  // @@protoc_insertion_point(parse_start:Protobuf.BigInt)
  for (;;) {
    ::std::pair< ::google::protobuf::uint32, bool> p = input->ReadTagWithCutoff(127);
    tag = p.first;
    if (!p.second) goto handle_unusual;
    switch (::google::protobuf::internal::WireFormatLite::GetTagFieldNumber(tag)) {
      // required bytes data = 1;
      case 1: {
        if (tag == 10) {
          DO_(::google::protobuf::internal::WireFormatLite::ReadBytes(
                input, this->mutable_data()));
        } else {
          goto handle_unusual;
        }
        if (input->ExpectAtEnd()) goto success;
        break;
      }

      default: {
      handle_unusual:
        if (tag == 0 ||
            ::google::protobuf::internal::WireFormatLite::GetTagWireType(tag) ==
            ::google::protobuf::internal::WireFormatLite::WIRETYPE_END_GROUP) {
          goto success;
        }
        DO_(::google::protobuf::internal::WireFormat::SkipField(
              input, tag, mutable_unknown_fields()));
        break;
      }
    }
  }
success:
  // @@protoc_insertion_point(parse_success:Protobuf.BigInt)
  return true;
failure:
  // @@protoc_insertion_point(parse_failure:Protobuf.BigInt)
  return false;
#undef DO_
}

void BigInt::SerializeWithCachedSizes(
    ::google::protobuf::io::CodedOutputStream* output) const {
  // @@protoc_insertion_point(serialize_start:Protobuf.BigInt)
  // required bytes data = 1;
  if (has_data()) {
    ::google::protobuf::internal::WireFormatLite::WriteBytesMaybeAliased(
      1, this->data(), output);
  }

  if (!unknown_fields().empty()) {
    ::google::protobuf::internal::WireFormat::SerializeUnknownFields(
        unknown_fields(), output);
  }
  // @@protoc_insertion_point(serialize_end:Protobuf.BigInt)
}

::google::protobuf::uint8* BigInt::SerializeWithCachedSizesToArray(
    ::google::protobuf::uint8* target) const {
  // @@protoc_insertion_point(serialize_to_array_start:Protobuf.BigInt)
  // required bytes data = 1;
  if (has_data()) {
    target =
      ::google::protobuf::internal::WireFormatLite::WriteBytesToArray(
        1, this->data(), target);
  }

  if (!unknown_fields().empty()) {
    target = ::google::protobuf::internal::WireFormat::SerializeUnknownFieldsToArray(
        unknown_fields(), target);
  }
  // @@protoc_insertion_point(serialize_to_array_end:Protobuf.BigInt)
  return target;
}

int BigInt::ByteSize() const {
  int total_size = 0;

  if (_has_bits_[0 / 32] & (0xffu << (0 % 32))) {
    // required bytes data = 1;
    if (has_data()) {
      total_size += 1 +
        ::google::protobuf::internal::WireFormatLite::BytesSize(
          this->data());
    }

  }
  if (!unknown_fields().empty()) {
    total_size +=
      ::google::protobuf::internal::WireFormat::ComputeUnknownFieldsSize(
        unknown_fields());
  }
  GOOGLE_SAFE_CONCURRENT_WRITES_BEGIN();
  _cached_size_ = total_size;
  GOOGLE_SAFE_CONCURRENT_WRITES_END();
  return total_size;
}

void BigInt::MergeFrom(const ::google::protobuf::Message& from) {
  GOOGLE_CHECK_NE(&from, this);
  const BigInt* source =
    ::google::protobuf::internal::dynamic_cast_if_available<const BigInt*>(
      &from);
  if (source == NULL) {
    ::google::protobuf::internal::ReflectionOps::Merge(from, this);
  } else {
    MergeFrom(*source);
  }
}

void BigInt::MergeFrom(const BigInt& from) {
  GOOGLE_CHECK_NE(&from, this);
  if (from._has_bits_[0 / 32] & (0xffu << (0 % 32))) {
    if (from.has_data()) {
      set_data(from.data());
    }
  }
  mutable_unknown_fields()->MergeFrom(from.unknown_fields());
}

void BigInt::CopyFrom(const ::google::protobuf::Message& from) {
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

void BigInt::CopyFrom(const BigInt& from) {
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

bool BigInt::IsInitialized() const {
  if ((_has_bits_[0] & 0x00000001) != 0x00000001) return false;

  return true;
}

void BigInt::Swap(BigInt* other) {
  if (other != this) {
    std::swap(data_, other->data_);
    std::swap(_has_bits_[0], other->_has_bits_[0]);
    _unknown_fields_.Swap(&other->_unknown_fields_);
    std::swap(_cached_size_, other->_cached_size_);
  }
}

::google::protobuf::Metadata BigInt::GetMetadata() const {
  protobuf_AssignDescriptorsOnce();
  ::google::protobuf::Metadata metadata;
  metadata.descriptor = BigInt_descriptor_;
  metadata.reflection = BigInt_reflection_;
  return metadata;
}


// ===================================================================

#ifndef _MSC_VER
const int BigIntArray::kValuesFieldNumber;
#endif  // !_MSC_VER

BigIntArray::BigIntArray()
  : ::google::protobuf::Message() {
  SharedCtor();
  // @@protoc_insertion_point(constructor:Protobuf.BigIntArray)
}

void BigIntArray::InitAsDefaultInstance() {
}

BigIntArray::BigIntArray(const BigIntArray& from)
  : ::google::protobuf::Message() {
  SharedCtor();
  MergeFrom(from);
  // @@protoc_insertion_point(copy_constructor:Protobuf.BigIntArray)
}

void BigIntArray::SharedCtor() {
  _cached_size_ = 0;
  ::memset(_has_bits_, 0, sizeof(_has_bits_));
}

BigIntArray::~BigIntArray() {
  // @@protoc_insertion_point(destructor:Protobuf.BigIntArray)
  SharedDtor();
}

void BigIntArray::SharedDtor() {
  if (this != default_instance_) {
  }
}

void BigIntArray::SetCachedSize(int size) const {
  GOOGLE_SAFE_CONCURRENT_WRITES_BEGIN();
  _cached_size_ = size;
  GOOGLE_SAFE_CONCURRENT_WRITES_END();
}
const ::google::protobuf::Descriptor* BigIntArray::descriptor() {
  protobuf_AssignDescriptorsOnce();
  return BigIntArray_descriptor_;
}

const BigIntArray& BigIntArray::default_instance() {
  if (default_instance_ == NULL) protobuf_AddDesc_bigint_2eproto();
  return *default_instance_;
}

BigIntArray* BigIntArray::default_instance_ = NULL;

BigIntArray* BigIntArray::New() const {
  return new BigIntArray;
}

void BigIntArray::Clear() {
  values_.Clear();
  ::memset(_has_bits_, 0, sizeof(_has_bits_));
  mutable_unknown_fields()->Clear();
}

bool BigIntArray::MergePartialFromCodedStream(
    ::google::protobuf::io::CodedInputStream* input) {
#define DO_(EXPRESSION) if (!(EXPRESSION)) goto failure
  ::google::protobuf::uint32 tag;
  // @@protoc_insertion_point(parse_start:Protobuf.BigIntArray)
  for (;;) {
    ::std::pair< ::google::protobuf::uint32, bool> p = input->ReadTagWithCutoff(127);
    tag = p.first;
    if (!p.second) goto handle_unusual;
    switch (::google::protobuf::internal::WireFormatLite::GetTagFieldNumber(tag)) {
      // repeated .Protobuf.BigInt values = 1;
      case 1: {
        if (tag == 10) {
         parse_values:
          DO_(::google::protobuf::internal::WireFormatLite::ReadMessageNoVirtual(
                input, add_values()));
        } else {
          goto handle_unusual;
        }
        if (input->ExpectTag(10)) goto parse_values;
        if (input->ExpectAtEnd()) goto success;
        break;
      }

      default: {
      handle_unusual:
        if (tag == 0 ||
            ::google::protobuf::internal::WireFormatLite::GetTagWireType(tag) ==
            ::google::protobuf::internal::WireFormatLite::WIRETYPE_END_GROUP) {
          goto success;
        }
        DO_(::google::protobuf::internal::WireFormat::SkipField(
              input, tag, mutable_unknown_fields()));
        break;
      }
    }
  }
success:
  // @@protoc_insertion_point(parse_success:Protobuf.BigIntArray)
  return true;
failure:
  // @@protoc_insertion_point(parse_failure:Protobuf.BigIntArray)
  return false;
#undef DO_
}

void BigIntArray::SerializeWithCachedSizes(
    ::google::protobuf::io::CodedOutputStream* output) const {
  // @@protoc_insertion_point(serialize_start:Protobuf.BigIntArray)
  // repeated .Protobuf.BigInt values = 1;
  for (int i = 0; i < this->values_size(); i++) {
    ::google::protobuf::internal::WireFormatLite::WriteMessageMaybeToArray(
      1, this->values(i), output);
  }

  if (!unknown_fields().empty()) {
    ::google::protobuf::internal::WireFormat::SerializeUnknownFields(
        unknown_fields(), output);
  }
  // @@protoc_insertion_point(serialize_end:Protobuf.BigIntArray)
}

::google::protobuf::uint8* BigIntArray::SerializeWithCachedSizesToArray(
    ::google::protobuf::uint8* target) const {
  // @@protoc_insertion_point(serialize_to_array_start:Protobuf.BigIntArray)
  // repeated .Protobuf.BigInt values = 1;
  for (int i = 0; i < this->values_size(); i++) {
    target = ::google::protobuf::internal::WireFormatLite::
      WriteMessageNoVirtualToArray(
        1, this->values(i), target);
  }

  if (!unknown_fields().empty()) {
    target = ::google::protobuf::internal::WireFormat::SerializeUnknownFieldsToArray(
        unknown_fields(), target);
  }
  // @@protoc_insertion_point(serialize_to_array_end:Protobuf.BigIntArray)
  return target;
}

int BigIntArray::ByteSize() const {
  int total_size = 0;

  // repeated .Protobuf.BigInt values = 1;
  total_size += 1 * this->values_size();
  for (int i = 0; i < this->values_size(); i++) {
    total_size +=
      ::google::protobuf::internal::WireFormatLite::MessageSizeNoVirtual(
        this->values(i));
  }

  if (!unknown_fields().empty()) {
    total_size +=
      ::google::protobuf::internal::WireFormat::ComputeUnknownFieldsSize(
        unknown_fields());
  }
  GOOGLE_SAFE_CONCURRENT_WRITES_BEGIN();
  _cached_size_ = total_size;
  GOOGLE_SAFE_CONCURRENT_WRITES_END();
  return total_size;
}

void BigIntArray::MergeFrom(const ::google::protobuf::Message& from) {
  GOOGLE_CHECK_NE(&from, this);
  const BigIntArray* source =
    ::google::protobuf::internal::dynamic_cast_if_available<const BigIntArray*>(
      &from);
  if (source == NULL) {
    ::google::protobuf::internal::ReflectionOps::Merge(from, this);
  } else {
    MergeFrom(*source);
  }
}

void BigIntArray::MergeFrom(const BigIntArray& from) {
  GOOGLE_CHECK_NE(&from, this);
  values_.MergeFrom(from.values_);
  mutable_unknown_fields()->MergeFrom(from.unknown_fields());
}

void BigIntArray::CopyFrom(const ::google::protobuf::Message& from) {
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

void BigIntArray::CopyFrom(const BigIntArray& from) {
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

bool BigIntArray::IsInitialized() const {

  if (!::google::protobuf::internal::AllAreInitialized(this->values())) return false;
  return true;
}

void BigIntArray::Swap(BigIntArray* other) {
  if (other != this) {
    values_.Swap(&other->values_);
    std::swap(_has_bits_[0], other->_has_bits_[0]);
    _unknown_fields_.Swap(&other->_unknown_fields_);
    std::swap(_cached_size_, other->_cached_size_);
  }
}

::google::protobuf::Metadata BigIntArray::GetMetadata() const {
  protobuf_AssignDescriptorsOnce();
  ::google::protobuf::Metadata metadata;
  metadata.descriptor = BigIntArray_descriptor_;
  metadata.reflection = BigIntArray_reflection_;
  return metadata;
}


// ===================================================================

#ifndef _MSC_VER
const int BigIntMatrix::kLinesFieldNumber;
#endif  // !_MSC_VER

BigIntMatrix::BigIntMatrix()
  : ::google::protobuf::Message() {
  SharedCtor();
  // @@protoc_insertion_point(constructor:Protobuf.BigIntMatrix)
}

void BigIntMatrix::InitAsDefaultInstance() {
}

BigIntMatrix::BigIntMatrix(const BigIntMatrix& from)
  : ::google::protobuf::Message() {
  SharedCtor();
  MergeFrom(from);
  // @@protoc_insertion_point(copy_constructor:Protobuf.BigIntMatrix)
}

void BigIntMatrix::SharedCtor() {
  _cached_size_ = 0;
  ::memset(_has_bits_, 0, sizeof(_has_bits_));
}

BigIntMatrix::~BigIntMatrix() {
  // @@protoc_insertion_point(destructor:Protobuf.BigIntMatrix)
  SharedDtor();
}

void BigIntMatrix::SharedDtor() {
  if (this != default_instance_) {
  }
}

void BigIntMatrix::SetCachedSize(int size) const {
  GOOGLE_SAFE_CONCURRENT_WRITES_BEGIN();
  _cached_size_ = size;
  GOOGLE_SAFE_CONCURRENT_WRITES_END();
}
const ::google::protobuf::Descriptor* BigIntMatrix::descriptor() {
  protobuf_AssignDescriptorsOnce();
  return BigIntMatrix_descriptor_;
}

const BigIntMatrix& BigIntMatrix::default_instance() {
  if (default_instance_ == NULL) protobuf_AddDesc_bigint_2eproto();
  return *default_instance_;
}

BigIntMatrix* BigIntMatrix::default_instance_ = NULL;

BigIntMatrix* BigIntMatrix::New() const {
  return new BigIntMatrix;
}

void BigIntMatrix::Clear() {
  lines_.Clear();
  ::memset(_has_bits_, 0, sizeof(_has_bits_));
  mutable_unknown_fields()->Clear();
}

bool BigIntMatrix::MergePartialFromCodedStream(
    ::google::protobuf::io::CodedInputStream* input) {
#define DO_(EXPRESSION) if (!(EXPRESSION)) goto failure
  ::google::protobuf::uint32 tag;
  // @@protoc_insertion_point(parse_start:Protobuf.BigIntMatrix)
  for (;;) {
    ::std::pair< ::google::protobuf::uint32, bool> p = input->ReadTagWithCutoff(127);
    tag = p.first;
    if (!p.second) goto handle_unusual;
    switch (::google::protobuf::internal::WireFormatLite::GetTagFieldNumber(tag)) {
      // repeated .Protobuf.BigIntArray lines = 1;
      case 1: {
        if (tag == 10) {
         parse_lines:
          DO_(::google::protobuf::internal::WireFormatLite::ReadMessageNoVirtual(
                input, add_lines()));
        } else {
          goto handle_unusual;
        }
        if (input->ExpectTag(10)) goto parse_lines;
        if (input->ExpectAtEnd()) goto success;
        break;
      }

      default: {
      handle_unusual:
        if (tag == 0 ||
            ::google::protobuf::internal::WireFormatLite::GetTagWireType(tag) ==
            ::google::protobuf::internal::WireFormatLite::WIRETYPE_END_GROUP) {
          goto success;
        }
        DO_(::google::protobuf::internal::WireFormat::SkipField(
              input, tag, mutable_unknown_fields()));
        break;
      }
    }
  }
success:
  // @@protoc_insertion_point(parse_success:Protobuf.BigIntMatrix)
  return true;
failure:
  // @@protoc_insertion_point(parse_failure:Protobuf.BigIntMatrix)
  return false;
#undef DO_
}

void BigIntMatrix::SerializeWithCachedSizes(
    ::google::protobuf::io::CodedOutputStream* output) const {
  // @@protoc_insertion_point(serialize_start:Protobuf.BigIntMatrix)
  // repeated .Protobuf.BigIntArray lines = 1;
  for (int i = 0; i < this->lines_size(); i++) {
    ::google::protobuf::internal::WireFormatLite::WriteMessageMaybeToArray(
      1, this->lines(i), output);
  }

  if (!unknown_fields().empty()) {
    ::google::protobuf::internal::WireFormat::SerializeUnknownFields(
        unknown_fields(), output);
  }
  // @@protoc_insertion_point(serialize_end:Protobuf.BigIntMatrix)
}

::google::protobuf::uint8* BigIntMatrix::SerializeWithCachedSizesToArray(
    ::google::protobuf::uint8* target) const {
  // @@protoc_insertion_point(serialize_to_array_start:Protobuf.BigIntMatrix)
  // repeated .Protobuf.BigIntArray lines = 1;
  for (int i = 0; i < this->lines_size(); i++) {
    target = ::google::protobuf::internal::WireFormatLite::
      WriteMessageNoVirtualToArray(
        1, this->lines(i), target);
  }

  if (!unknown_fields().empty()) {
    target = ::google::protobuf::internal::WireFormat::SerializeUnknownFieldsToArray(
        unknown_fields(), target);
  }
  // @@protoc_insertion_point(serialize_to_array_end:Protobuf.BigIntMatrix)
  return target;
}

int BigIntMatrix::ByteSize() const {
  int total_size = 0;

  // repeated .Protobuf.BigIntArray lines = 1;
  total_size += 1 * this->lines_size();
  for (int i = 0; i < this->lines_size(); i++) {
    total_size +=
      ::google::protobuf::internal::WireFormatLite::MessageSizeNoVirtual(
        this->lines(i));
  }

  if (!unknown_fields().empty()) {
    total_size +=
      ::google::protobuf::internal::WireFormat::ComputeUnknownFieldsSize(
        unknown_fields());
  }
  GOOGLE_SAFE_CONCURRENT_WRITES_BEGIN();
  _cached_size_ = total_size;
  GOOGLE_SAFE_CONCURRENT_WRITES_END();
  return total_size;
}

void BigIntMatrix::MergeFrom(const ::google::protobuf::Message& from) {
  GOOGLE_CHECK_NE(&from, this);
  const BigIntMatrix* source =
    ::google::protobuf::internal::dynamic_cast_if_available<const BigIntMatrix*>(
      &from);
  if (source == NULL) {
    ::google::protobuf::internal::ReflectionOps::Merge(from, this);
  } else {
    MergeFrom(*source);
  }
}

void BigIntMatrix::MergeFrom(const BigIntMatrix& from) {
  GOOGLE_CHECK_NE(&from, this);
  lines_.MergeFrom(from.lines_);
  mutable_unknown_fields()->MergeFrom(from.unknown_fields());
}

void BigIntMatrix::CopyFrom(const ::google::protobuf::Message& from) {
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

void BigIntMatrix::CopyFrom(const BigIntMatrix& from) {
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

bool BigIntMatrix::IsInitialized() const {

  if (!::google::protobuf::internal::AllAreInitialized(this->lines())) return false;
  return true;
}

void BigIntMatrix::Swap(BigIntMatrix* other) {
  if (other != this) {
    lines_.Swap(&other->lines_);
    std::swap(_has_bits_[0], other->_has_bits_[0]);
    _unknown_fields_.Swap(&other->_unknown_fields_);
    std::swap(_cached_size_, other->_cached_size_);
  }
}

::google::protobuf::Metadata BigIntMatrix::GetMetadata() const {
  protobuf_AssignDescriptorsOnce();
  ::google::protobuf::Metadata metadata;
  metadata.descriptor = BigIntMatrix_descriptor_;
  metadata.reflection = BigIntMatrix_reflection_;
  return metadata;
}


// ===================================================================

#ifndef _MSC_VER
const int BigIntMatrix_Collection::kMatricesFieldNumber;
#endif  // !_MSC_VER

BigIntMatrix_Collection::BigIntMatrix_Collection()
  : ::google::protobuf::Message() {
  SharedCtor();
  // @@protoc_insertion_point(constructor:Protobuf.BigIntMatrix_Collection)
}

void BigIntMatrix_Collection::InitAsDefaultInstance() {
}

BigIntMatrix_Collection::BigIntMatrix_Collection(const BigIntMatrix_Collection& from)
  : ::google::protobuf::Message() {
  SharedCtor();
  MergeFrom(from);
  // @@protoc_insertion_point(copy_constructor:Protobuf.BigIntMatrix_Collection)
}

void BigIntMatrix_Collection::SharedCtor() {
  _cached_size_ = 0;
  ::memset(_has_bits_, 0, sizeof(_has_bits_));
}

BigIntMatrix_Collection::~BigIntMatrix_Collection() {
  // @@protoc_insertion_point(destructor:Protobuf.BigIntMatrix_Collection)
  SharedDtor();
}

void BigIntMatrix_Collection::SharedDtor() {
  if (this != default_instance_) {
  }
}

void BigIntMatrix_Collection::SetCachedSize(int size) const {
  GOOGLE_SAFE_CONCURRENT_WRITES_BEGIN();
  _cached_size_ = size;
  GOOGLE_SAFE_CONCURRENT_WRITES_END();
}
const ::google::protobuf::Descriptor* BigIntMatrix_Collection::descriptor() {
  protobuf_AssignDescriptorsOnce();
  return BigIntMatrix_Collection_descriptor_;
}

const BigIntMatrix_Collection& BigIntMatrix_Collection::default_instance() {
  if (default_instance_ == NULL) protobuf_AddDesc_bigint_2eproto();
  return *default_instance_;
}

BigIntMatrix_Collection* BigIntMatrix_Collection::default_instance_ = NULL;

BigIntMatrix_Collection* BigIntMatrix_Collection::New() const {
  return new BigIntMatrix_Collection;
}

void BigIntMatrix_Collection::Clear() {
  matrices_.Clear();
  ::memset(_has_bits_, 0, sizeof(_has_bits_));
  mutable_unknown_fields()->Clear();
}

bool BigIntMatrix_Collection::MergePartialFromCodedStream(
    ::google::protobuf::io::CodedInputStream* input) {
#define DO_(EXPRESSION) if (!(EXPRESSION)) goto failure
  ::google::protobuf::uint32 tag;
  // @@protoc_insertion_point(parse_start:Protobuf.BigIntMatrix_Collection)
  for (;;) {
    ::std::pair< ::google::protobuf::uint32, bool> p = input->ReadTagWithCutoff(127);
    tag = p.first;
    if (!p.second) goto handle_unusual;
    switch (::google::protobuf::internal::WireFormatLite::GetTagFieldNumber(tag)) {
      // repeated .Protobuf.BigIntMatrix matrices = 1;
      case 1: {
        if (tag == 10) {
         parse_matrices:
          DO_(::google::protobuf::internal::WireFormatLite::ReadMessageNoVirtual(
                input, add_matrices()));
        } else {
          goto handle_unusual;
        }
        if (input->ExpectTag(10)) goto parse_matrices;
        if (input->ExpectAtEnd()) goto success;
        break;
      }

      default: {
      handle_unusual:
        if (tag == 0 ||
            ::google::protobuf::internal::WireFormatLite::GetTagWireType(tag) ==
            ::google::protobuf::internal::WireFormatLite::WIRETYPE_END_GROUP) {
          goto success;
        }
        DO_(::google::protobuf::internal::WireFormat::SkipField(
              input, tag, mutable_unknown_fields()));
        break;
      }
    }
  }
success:
  // @@protoc_insertion_point(parse_success:Protobuf.BigIntMatrix_Collection)
  return true;
failure:
  // @@protoc_insertion_point(parse_failure:Protobuf.BigIntMatrix_Collection)
  return false;
#undef DO_
}

void BigIntMatrix_Collection::SerializeWithCachedSizes(
    ::google::protobuf::io::CodedOutputStream* output) const {
  // @@protoc_insertion_point(serialize_start:Protobuf.BigIntMatrix_Collection)
  // repeated .Protobuf.BigIntMatrix matrices = 1;
  for (int i = 0; i < this->matrices_size(); i++) {
    ::google::protobuf::internal::WireFormatLite::WriteMessageMaybeToArray(
      1, this->matrices(i), output);
  }

  if (!unknown_fields().empty()) {
    ::google::protobuf::internal::WireFormat::SerializeUnknownFields(
        unknown_fields(), output);
  }
  // @@protoc_insertion_point(serialize_end:Protobuf.BigIntMatrix_Collection)
}

::google::protobuf::uint8* BigIntMatrix_Collection::SerializeWithCachedSizesToArray(
    ::google::protobuf::uint8* target) const {
  // @@protoc_insertion_point(serialize_to_array_start:Protobuf.BigIntMatrix_Collection)
  // repeated .Protobuf.BigIntMatrix matrices = 1;
  for (int i = 0; i < this->matrices_size(); i++) {
    target = ::google::protobuf::internal::WireFormatLite::
      WriteMessageNoVirtualToArray(
        1, this->matrices(i), target);
  }

  if (!unknown_fields().empty()) {
    target = ::google::protobuf::internal::WireFormat::SerializeUnknownFieldsToArray(
        unknown_fields(), target);
  }
  // @@protoc_insertion_point(serialize_to_array_end:Protobuf.BigIntMatrix_Collection)
  return target;
}

int BigIntMatrix_Collection::ByteSize() const {
  int total_size = 0;

  // repeated .Protobuf.BigIntMatrix matrices = 1;
  total_size += 1 * this->matrices_size();
  for (int i = 0; i < this->matrices_size(); i++) {
    total_size +=
      ::google::protobuf::internal::WireFormatLite::MessageSizeNoVirtual(
        this->matrices(i));
  }

  if (!unknown_fields().empty()) {
    total_size +=
      ::google::protobuf::internal::WireFormat::ComputeUnknownFieldsSize(
        unknown_fields());
  }
  GOOGLE_SAFE_CONCURRENT_WRITES_BEGIN();
  _cached_size_ = total_size;
  GOOGLE_SAFE_CONCURRENT_WRITES_END();
  return total_size;
}

void BigIntMatrix_Collection::MergeFrom(const ::google::protobuf::Message& from) {
  GOOGLE_CHECK_NE(&from, this);
  const BigIntMatrix_Collection* source =
    ::google::protobuf::internal::dynamic_cast_if_available<const BigIntMatrix_Collection*>(
      &from);
  if (source == NULL) {
    ::google::protobuf::internal::ReflectionOps::Merge(from, this);
  } else {
    MergeFrom(*source);
  }
}

void BigIntMatrix_Collection::MergeFrom(const BigIntMatrix_Collection& from) {
  GOOGLE_CHECK_NE(&from, this);
  matrices_.MergeFrom(from.matrices_);
  mutable_unknown_fields()->MergeFrom(from.unknown_fields());
}

void BigIntMatrix_Collection::CopyFrom(const ::google::protobuf::Message& from) {
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

void BigIntMatrix_Collection::CopyFrom(const BigIntMatrix_Collection& from) {
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

bool BigIntMatrix_Collection::IsInitialized() const {

  if (!::google::protobuf::internal::AllAreInitialized(this->matrices())) return false;
  return true;
}

void BigIntMatrix_Collection::Swap(BigIntMatrix_Collection* other) {
  if (other != this) {
    matrices_.Swap(&other->matrices_);
    std::swap(_has_bits_[0], other->_has_bits_[0]);
    _unknown_fields_.Swap(&other->_unknown_fields_);
    std::swap(_cached_size_, other->_cached_size_);
  }
}

::google::protobuf::Metadata BigIntMatrix_Collection::GetMetadata() const {
  protobuf_AssignDescriptorsOnce();
  ::google::protobuf::Metadata metadata;
  metadata.descriptor = BigIntMatrix_Collection_descriptor_;
  metadata.reflection = BigIntMatrix_Collection_reflection_;
  return metadata;
}


// @@protoc_insertion_point(namespace_scope)

}  // namespace Protobuf

// @@protoc_insertion_point(global_scope)
