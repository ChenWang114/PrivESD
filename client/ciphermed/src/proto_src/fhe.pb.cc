// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: fhe.proto

#define INTERNAL_SUPPRESS_PROTOBUF_FIELD_DEPRECATION
#include "fhe.pb.h"

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

const ::google::protobuf::Descriptor* FHE_Context_descriptor_ = NULL;
const ::google::protobuf::internal::GeneratedMessageReflection*
  FHE_Context_reflection_ = NULL;
const ::google::protobuf::Descriptor* FHE_PK_descriptor_ = NULL;
const ::google::protobuf::internal::GeneratedMessageReflection*
  FHE_PK_reflection_ = NULL;
const ::google::protobuf::Descriptor* FHE_Ctxt_descriptor_ = NULL;
const ::google::protobuf::internal::GeneratedMessageReflection*
  FHE_Ctxt_reflection_ = NULL;

}  // namespace


void protobuf_AssignDesc_fhe_2eproto() {
  protobuf_AddDesc_fhe_2eproto();
  const ::google::protobuf::FileDescriptor* file =
    ::google::protobuf::DescriptorPool::generated_pool()->FindFileByName(
      "fhe.proto");
  GOOGLE_CHECK(file != NULL);
  FHE_Context_descriptor_ = file->message_type(0);
  static const int FHE_Context_offsets_[1] = {
    GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(FHE_Context, content_),
  };
  FHE_Context_reflection_ =
    new ::google::protobuf::internal::GeneratedMessageReflection(
      FHE_Context_descriptor_,
      FHE_Context::default_instance_,
      FHE_Context_offsets_,
      GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(FHE_Context, _has_bits_[0]),
      GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(FHE_Context, _unknown_fields_),
      -1,
      ::google::protobuf::DescriptorPool::generated_pool(),
      ::google::protobuf::MessageFactory::generated_factory(),
      sizeof(FHE_Context));
  FHE_PK_descriptor_ = file->message_type(1);
  static const int FHE_PK_offsets_[1] = {
    GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(FHE_PK, content_),
  };
  FHE_PK_reflection_ =
    new ::google::protobuf::internal::GeneratedMessageReflection(
      FHE_PK_descriptor_,
      FHE_PK::default_instance_,
      FHE_PK_offsets_,
      GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(FHE_PK, _has_bits_[0]),
      GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(FHE_PK, _unknown_fields_),
      -1,
      ::google::protobuf::DescriptorPool::generated_pool(),
      ::google::protobuf::MessageFactory::generated_factory(),
      sizeof(FHE_PK));
  FHE_Ctxt_descriptor_ = file->message_type(2);
  static const int FHE_Ctxt_offsets_[1] = {
    GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(FHE_Ctxt, content_),
  };
  FHE_Ctxt_reflection_ =
    new ::google::protobuf::internal::GeneratedMessageReflection(
      FHE_Ctxt_descriptor_,
      FHE_Ctxt::default_instance_,
      FHE_Ctxt_offsets_,
      GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(FHE_Ctxt, _has_bits_[0]),
      GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(FHE_Ctxt, _unknown_fields_),
      -1,
      ::google::protobuf::DescriptorPool::generated_pool(),
      ::google::protobuf::MessageFactory::generated_factory(),
      sizeof(FHE_Ctxt));
}

namespace {

GOOGLE_PROTOBUF_DECLARE_ONCE(protobuf_AssignDescriptors_once_);
inline void protobuf_AssignDescriptorsOnce() {
  ::google::protobuf::GoogleOnceInit(&protobuf_AssignDescriptors_once_,
                 &protobuf_AssignDesc_fhe_2eproto);
}

void protobuf_RegisterTypes(const ::std::string&) {
  protobuf_AssignDescriptorsOnce();
  ::google::protobuf::MessageFactory::InternalRegisterGeneratedMessage(
    FHE_Context_descriptor_, &FHE_Context::default_instance());
  ::google::protobuf::MessageFactory::InternalRegisterGeneratedMessage(
    FHE_PK_descriptor_, &FHE_PK::default_instance());
  ::google::protobuf::MessageFactory::InternalRegisterGeneratedMessage(
    FHE_Ctxt_descriptor_, &FHE_Ctxt::default_instance());
}

}  // namespace

void protobuf_ShutdownFile_fhe_2eproto() {
  delete FHE_Context::default_instance_;
  delete FHE_Context_reflection_;
  delete FHE_PK::default_instance_;
  delete FHE_PK_reflection_;
  delete FHE_Ctxt::default_instance_;
  delete FHE_Ctxt_reflection_;
}

void protobuf_AddDesc_fhe_2eproto() {
  static bool already_here = false;
  if (already_here) return;
  already_here = true;
  GOOGLE_PROTOBUF_VERIFY_VERSION;

  ::google::protobuf::DescriptorPool::InternalAddGeneratedFile(
    "\n\tfhe.proto\022\010Protobuf\"\036\n\013FHE_Context\022\017\n\007"
    "content\030\001 \002(\t\"\031\n\006FHE_PK\022\017\n\007content\030\001 \002(\t"
    "\"\033\n\010FHE_Ctxt\022\017\n\007content\030\001 \002(\t", 109);
  ::google::protobuf::MessageFactory::InternalRegisterGeneratedFile(
    "fhe.proto", &protobuf_RegisterTypes);
  FHE_Context::default_instance_ = new FHE_Context();
  FHE_PK::default_instance_ = new FHE_PK();
  FHE_Ctxt::default_instance_ = new FHE_Ctxt();
  FHE_Context::default_instance_->InitAsDefaultInstance();
  FHE_PK::default_instance_->InitAsDefaultInstance();
  FHE_Ctxt::default_instance_->InitAsDefaultInstance();
  ::google::protobuf::internal::OnShutdown(&protobuf_ShutdownFile_fhe_2eproto);
}

// Force AddDescriptors() to be called at static initialization time.
struct StaticDescriptorInitializer_fhe_2eproto {
  StaticDescriptorInitializer_fhe_2eproto() {
    protobuf_AddDesc_fhe_2eproto();
  }
} static_descriptor_initializer_fhe_2eproto_;

// ===================================================================

#ifndef _MSC_VER
const int FHE_Context::kContentFieldNumber;
#endif  // !_MSC_VER

FHE_Context::FHE_Context()
  : ::google::protobuf::Message() {
  SharedCtor();
  // @@protoc_insertion_point(constructor:Protobuf.FHE_Context)
}

void FHE_Context::InitAsDefaultInstance() {
}

FHE_Context::FHE_Context(const FHE_Context& from)
  : ::google::protobuf::Message() {
  SharedCtor();
  MergeFrom(from);
  // @@protoc_insertion_point(copy_constructor:Protobuf.FHE_Context)
}

void FHE_Context::SharedCtor() {
  ::google::protobuf::internal::GetEmptyString();
  _cached_size_ = 0;
  content_ = const_cast< ::std::string*>(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
  ::memset(_has_bits_, 0, sizeof(_has_bits_));
}

FHE_Context::~FHE_Context() {
  // @@protoc_insertion_point(destructor:Protobuf.FHE_Context)
  SharedDtor();
}

void FHE_Context::SharedDtor() {
  if (content_ != &::google::protobuf::internal::GetEmptyStringAlreadyInited()) {
    delete content_;
  }
  if (this != default_instance_) {
  }
}

void FHE_Context::SetCachedSize(int size) const {
  GOOGLE_SAFE_CONCURRENT_WRITES_BEGIN();
  _cached_size_ = size;
  GOOGLE_SAFE_CONCURRENT_WRITES_END();
}
const ::google::protobuf::Descriptor* FHE_Context::descriptor() {
  protobuf_AssignDescriptorsOnce();
  return FHE_Context_descriptor_;
}

const FHE_Context& FHE_Context::default_instance() {
  if (default_instance_ == NULL) protobuf_AddDesc_fhe_2eproto();
  return *default_instance_;
}

FHE_Context* FHE_Context::default_instance_ = NULL;

FHE_Context* FHE_Context::New() const {
  return new FHE_Context;
}

void FHE_Context::Clear() {
  if (has_content()) {
    if (content_ != &::google::protobuf::internal::GetEmptyStringAlreadyInited()) {
      content_->clear();
    }
  }
  ::memset(_has_bits_, 0, sizeof(_has_bits_));
  mutable_unknown_fields()->Clear();
}

bool FHE_Context::MergePartialFromCodedStream(
    ::google::protobuf::io::CodedInputStream* input) {
#define DO_(EXPRESSION) if (!(EXPRESSION)) goto failure
  ::google::protobuf::uint32 tag;
  // @@protoc_insertion_point(parse_start:Protobuf.FHE_Context)
  for (;;) {
    ::std::pair< ::google::protobuf::uint32, bool> p = input->ReadTagWithCutoff(127);
    tag = p.first;
    if (!p.second) goto handle_unusual;
    switch (::google::protobuf::internal::WireFormatLite::GetTagFieldNumber(tag)) {
      // required string content = 1;
      case 1: {
        if (tag == 10) {
          DO_(::google::protobuf::internal::WireFormatLite::ReadString(
                input, this->mutable_content()));
          ::google::protobuf::internal::WireFormat::VerifyUTF8StringNamedField(
            this->content().data(), this->content().length(),
            ::google::protobuf::internal::WireFormat::PARSE,
            "content");
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
  // @@protoc_insertion_point(parse_success:Protobuf.FHE_Context)
  return true;
failure:
  // @@protoc_insertion_point(parse_failure:Protobuf.FHE_Context)
  return false;
#undef DO_
}

void FHE_Context::SerializeWithCachedSizes(
    ::google::protobuf::io::CodedOutputStream* output) const {
  // @@protoc_insertion_point(serialize_start:Protobuf.FHE_Context)
  // required string content = 1;
  if (has_content()) {
    ::google::protobuf::internal::WireFormat::VerifyUTF8StringNamedField(
      this->content().data(), this->content().length(),
      ::google::protobuf::internal::WireFormat::SERIALIZE,
      "content");
    ::google::protobuf::internal::WireFormatLite::WriteStringMaybeAliased(
      1, this->content(), output);
  }

  if (!unknown_fields().empty()) {
    ::google::protobuf::internal::WireFormat::SerializeUnknownFields(
        unknown_fields(), output);
  }
  // @@protoc_insertion_point(serialize_end:Protobuf.FHE_Context)
}

::google::protobuf::uint8* FHE_Context::SerializeWithCachedSizesToArray(
    ::google::protobuf::uint8* target) const {
  // @@protoc_insertion_point(serialize_to_array_start:Protobuf.FHE_Context)
  // required string content = 1;
  if (has_content()) {
    ::google::protobuf::internal::WireFormat::VerifyUTF8StringNamedField(
      this->content().data(), this->content().length(),
      ::google::protobuf::internal::WireFormat::SERIALIZE,
      "content");
    target =
      ::google::protobuf::internal::WireFormatLite::WriteStringToArray(
        1, this->content(), target);
  }

  if (!unknown_fields().empty()) {
    target = ::google::protobuf::internal::WireFormat::SerializeUnknownFieldsToArray(
        unknown_fields(), target);
  }
  // @@protoc_insertion_point(serialize_to_array_end:Protobuf.FHE_Context)
  return target;
}

int FHE_Context::ByteSize() const {
  int total_size = 0;

  if (_has_bits_[0 / 32] & (0xffu << (0 % 32))) {
    // required string content = 1;
    if (has_content()) {
      total_size += 1 +
        ::google::protobuf::internal::WireFormatLite::StringSize(
          this->content());
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

void FHE_Context::MergeFrom(const ::google::protobuf::Message& from) {
  GOOGLE_CHECK_NE(&from, this);
  const FHE_Context* source =
    ::google::protobuf::internal::dynamic_cast_if_available<const FHE_Context*>(
      &from);
  if (source == NULL) {
    ::google::protobuf::internal::ReflectionOps::Merge(from, this);
  } else {
    MergeFrom(*source);
  }
}

void FHE_Context::MergeFrom(const FHE_Context& from) {
  GOOGLE_CHECK_NE(&from, this);
  if (from._has_bits_[0 / 32] & (0xffu << (0 % 32))) {
    if (from.has_content()) {
      set_content(from.content());
    }
  }
  mutable_unknown_fields()->MergeFrom(from.unknown_fields());
}

void FHE_Context::CopyFrom(const ::google::protobuf::Message& from) {
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

void FHE_Context::CopyFrom(const FHE_Context& from) {
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

bool FHE_Context::IsInitialized() const {
  if ((_has_bits_[0] & 0x00000001) != 0x00000001) return false;

  return true;
}

void FHE_Context::Swap(FHE_Context* other) {
  if (other != this) {
    std::swap(content_, other->content_);
    std::swap(_has_bits_[0], other->_has_bits_[0]);
    _unknown_fields_.Swap(&other->_unknown_fields_);
    std::swap(_cached_size_, other->_cached_size_);
  }
}

::google::protobuf::Metadata FHE_Context::GetMetadata() const {
  protobuf_AssignDescriptorsOnce();
  ::google::protobuf::Metadata metadata;
  metadata.descriptor = FHE_Context_descriptor_;
  metadata.reflection = FHE_Context_reflection_;
  return metadata;
}


// ===================================================================

#ifndef _MSC_VER
const int FHE_PK::kContentFieldNumber;
#endif  // !_MSC_VER

FHE_PK::FHE_PK()
  : ::google::protobuf::Message() {
  SharedCtor();
  // @@protoc_insertion_point(constructor:Protobuf.FHE_PK)
}

void FHE_PK::InitAsDefaultInstance() {
}

FHE_PK::FHE_PK(const FHE_PK& from)
  : ::google::protobuf::Message() {
  SharedCtor();
  MergeFrom(from);
  // @@protoc_insertion_point(copy_constructor:Protobuf.FHE_PK)
}

void FHE_PK::SharedCtor() {
  ::google::protobuf::internal::GetEmptyString();
  _cached_size_ = 0;
  content_ = const_cast< ::std::string*>(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
  ::memset(_has_bits_, 0, sizeof(_has_bits_));
}

FHE_PK::~FHE_PK() {
  // @@protoc_insertion_point(destructor:Protobuf.FHE_PK)
  SharedDtor();
}

void FHE_PK::SharedDtor() {
  if (content_ != &::google::protobuf::internal::GetEmptyStringAlreadyInited()) {
    delete content_;
  }
  if (this != default_instance_) {
  }
}

void FHE_PK::SetCachedSize(int size) const {
  GOOGLE_SAFE_CONCURRENT_WRITES_BEGIN();
  _cached_size_ = size;
  GOOGLE_SAFE_CONCURRENT_WRITES_END();
}
const ::google::protobuf::Descriptor* FHE_PK::descriptor() {
  protobuf_AssignDescriptorsOnce();
  return FHE_PK_descriptor_;
}

const FHE_PK& FHE_PK::default_instance() {
  if (default_instance_ == NULL) protobuf_AddDesc_fhe_2eproto();
  return *default_instance_;
}

FHE_PK* FHE_PK::default_instance_ = NULL;

FHE_PK* FHE_PK::New() const {
  return new FHE_PK;
}

void FHE_PK::Clear() {
  if (has_content()) {
    if (content_ != &::google::protobuf::internal::GetEmptyStringAlreadyInited()) {
      content_->clear();
    }
  }
  ::memset(_has_bits_, 0, sizeof(_has_bits_));
  mutable_unknown_fields()->Clear();
}

bool FHE_PK::MergePartialFromCodedStream(
    ::google::protobuf::io::CodedInputStream* input) {
#define DO_(EXPRESSION) if (!(EXPRESSION)) goto failure
  ::google::protobuf::uint32 tag;
  // @@protoc_insertion_point(parse_start:Protobuf.FHE_PK)
  for (;;) {
    ::std::pair< ::google::protobuf::uint32, bool> p = input->ReadTagWithCutoff(127);
    tag = p.first;
    if (!p.second) goto handle_unusual;
    switch (::google::protobuf::internal::WireFormatLite::GetTagFieldNumber(tag)) {
      // required string content = 1;
      case 1: {
        if (tag == 10) {
          DO_(::google::protobuf::internal::WireFormatLite::ReadString(
                input, this->mutable_content()));
          ::google::protobuf::internal::WireFormat::VerifyUTF8StringNamedField(
            this->content().data(), this->content().length(),
            ::google::protobuf::internal::WireFormat::PARSE,
            "content");
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
  // @@protoc_insertion_point(parse_success:Protobuf.FHE_PK)
  return true;
failure:
  // @@protoc_insertion_point(parse_failure:Protobuf.FHE_PK)
  return false;
#undef DO_
}

void FHE_PK::SerializeWithCachedSizes(
    ::google::protobuf::io::CodedOutputStream* output) const {
  // @@protoc_insertion_point(serialize_start:Protobuf.FHE_PK)
  // required string content = 1;
  if (has_content()) {
    ::google::protobuf::internal::WireFormat::VerifyUTF8StringNamedField(
      this->content().data(), this->content().length(),
      ::google::protobuf::internal::WireFormat::SERIALIZE,
      "content");
    ::google::protobuf::internal::WireFormatLite::WriteStringMaybeAliased(
      1, this->content(), output);
  }

  if (!unknown_fields().empty()) {
    ::google::protobuf::internal::WireFormat::SerializeUnknownFields(
        unknown_fields(), output);
  }
  // @@protoc_insertion_point(serialize_end:Protobuf.FHE_PK)
}

::google::protobuf::uint8* FHE_PK::SerializeWithCachedSizesToArray(
    ::google::protobuf::uint8* target) const {
  // @@protoc_insertion_point(serialize_to_array_start:Protobuf.FHE_PK)
  // required string content = 1;
  if (has_content()) {
    ::google::protobuf::internal::WireFormat::VerifyUTF8StringNamedField(
      this->content().data(), this->content().length(),
      ::google::protobuf::internal::WireFormat::SERIALIZE,
      "content");
    target =
      ::google::protobuf::internal::WireFormatLite::WriteStringToArray(
        1, this->content(), target);
  }

  if (!unknown_fields().empty()) {
    target = ::google::protobuf::internal::WireFormat::SerializeUnknownFieldsToArray(
        unknown_fields(), target);
  }
  // @@protoc_insertion_point(serialize_to_array_end:Protobuf.FHE_PK)
  return target;
}

int FHE_PK::ByteSize() const {
  int total_size = 0;

  if (_has_bits_[0 / 32] & (0xffu << (0 % 32))) {
    // required string content = 1;
    if (has_content()) {
      total_size += 1 +
        ::google::protobuf::internal::WireFormatLite::StringSize(
          this->content());
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

void FHE_PK::MergeFrom(const ::google::protobuf::Message& from) {
  GOOGLE_CHECK_NE(&from, this);
  const FHE_PK* source =
    ::google::protobuf::internal::dynamic_cast_if_available<const FHE_PK*>(
      &from);
  if (source == NULL) {
    ::google::protobuf::internal::ReflectionOps::Merge(from, this);
  } else {
    MergeFrom(*source);
  }
}

void FHE_PK::MergeFrom(const FHE_PK& from) {
  GOOGLE_CHECK_NE(&from, this);
  if (from._has_bits_[0 / 32] & (0xffu << (0 % 32))) {
    if (from.has_content()) {
      set_content(from.content());
    }
  }
  mutable_unknown_fields()->MergeFrom(from.unknown_fields());
}

void FHE_PK::CopyFrom(const ::google::protobuf::Message& from) {
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

void FHE_PK::CopyFrom(const FHE_PK& from) {
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

bool FHE_PK::IsInitialized() const {
  if ((_has_bits_[0] & 0x00000001) != 0x00000001) return false;

  return true;
}

void FHE_PK::Swap(FHE_PK* other) {
  if (other != this) {
    std::swap(content_, other->content_);
    std::swap(_has_bits_[0], other->_has_bits_[0]);
    _unknown_fields_.Swap(&other->_unknown_fields_);
    std::swap(_cached_size_, other->_cached_size_);
  }
}

::google::protobuf::Metadata FHE_PK::GetMetadata() const {
  protobuf_AssignDescriptorsOnce();
  ::google::protobuf::Metadata metadata;
  metadata.descriptor = FHE_PK_descriptor_;
  metadata.reflection = FHE_PK_reflection_;
  return metadata;
}


// ===================================================================

#ifndef _MSC_VER
const int FHE_Ctxt::kContentFieldNumber;
#endif  // !_MSC_VER

FHE_Ctxt::FHE_Ctxt()
  : ::google::protobuf::Message() {
  SharedCtor();
  // @@protoc_insertion_point(constructor:Protobuf.FHE_Ctxt)
}

void FHE_Ctxt::InitAsDefaultInstance() {
}

FHE_Ctxt::FHE_Ctxt(const FHE_Ctxt& from)
  : ::google::protobuf::Message() {
  SharedCtor();
  MergeFrom(from);
  // @@protoc_insertion_point(copy_constructor:Protobuf.FHE_Ctxt)
}

void FHE_Ctxt::SharedCtor() {
  ::google::protobuf::internal::GetEmptyString();
  _cached_size_ = 0;
  content_ = const_cast< ::std::string*>(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
  ::memset(_has_bits_, 0, sizeof(_has_bits_));
}

FHE_Ctxt::~FHE_Ctxt() {
  // @@protoc_insertion_point(destructor:Protobuf.FHE_Ctxt)
  SharedDtor();
}

void FHE_Ctxt::SharedDtor() {
  if (content_ != &::google::protobuf::internal::GetEmptyStringAlreadyInited()) {
    delete content_;
  }
  if (this != default_instance_) {
  }
}

void FHE_Ctxt::SetCachedSize(int size) const {
  GOOGLE_SAFE_CONCURRENT_WRITES_BEGIN();
  _cached_size_ = size;
  GOOGLE_SAFE_CONCURRENT_WRITES_END();
}
const ::google::protobuf::Descriptor* FHE_Ctxt::descriptor() {
  protobuf_AssignDescriptorsOnce();
  return FHE_Ctxt_descriptor_;
}

const FHE_Ctxt& FHE_Ctxt::default_instance() {
  if (default_instance_ == NULL) protobuf_AddDesc_fhe_2eproto();
  return *default_instance_;
}

FHE_Ctxt* FHE_Ctxt::default_instance_ = NULL;

FHE_Ctxt* FHE_Ctxt::New() const {
  return new FHE_Ctxt;
}

void FHE_Ctxt::Clear() {
  if (has_content()) {
    if (content_ != &::google::protobuf::internal::GetEmptyStringAlreadyInited()) {
      content_->clear();
    }
  }
  ::memset(_has_bits_, 0, sizeof(_has_bits_));
  mutable_unknown_fields()->Clear();
}

bool FHE_Ctxt::MergePartialFromCodedStream(
    ::google::protobuf::io::CodedInputStream* input) {
#define DO_(EXPRESSION) if (!(EXPRESSION)) goto failure
  ::google::protobuf::uint32 tag;
  // @@protoc_insertion_point(parse_start:Protobuf.FHE_Ctxt)
  for (;;) {
    ::std::pair< ::google::protobuf::uint32, bool> p = input->ReadTagWithCutoff(127);
    tag = p.first;
    if (!p.second) goto handle_unusual;
    switch (::google::protobuf::internal::WireFormatLite::GetTagFieldNumber(tag)) {
      // required string content = 1;
      case 1: {
        if (tag == 10) {
          DO_(::google::protobuf::internal::WireFormatLite::ReadString(
                input, this->mutable_content()));
          ::google::protobuf::internal::WireFormat::VerifyUTF8StringNamedField(
            this->content().data(), this->content().length(),
            ::google::protobuf::internal::WireFormat::PARSE,
            "content");
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
  // @@protoc_insertion_point(parse_success:Protobuf.FHE_Ctxt)
  return true;
failure:
  // @@protoc_insertion_point(parse_failure:Protobuf.FHE_Ctxt)
  return false;
#undef DO_
}

void FHE_Ctxt::SerializeWithCachedSizes(
    ::google::protobuf::io::CodedOutputStream* output) const {
  // @@protoc_insertion_point(serialize_start:Protobuf.FHE_Ctxt)
  // required string content = 1;
  if (has_content()) {
    ::google::protobuf::internal::WireFormat::VerifyUTF8StringNamedField(
      this->content().data(), this->content().length(),
      ::google::protobuf::internal::WireFormat::SERIALIZE,
      "content");
    ::google::protobuf::internal::WireFormatLite::WriteStringMaybeAliased(
      1, this->content(), output);
  }

  if (!unknown_fields().empty()) {
    ::google::protobuf::internal::WireFormat::SerializeUnknownFields(
        unknown_fields(), output);
  }
  // @@protoc_insertion_point(serialize_end:Protobuf.FHE_Ctxt)
}

::google::protobuf::uint8* FHE_Ctxt::SerializeWithCachedSizesToArray(
    ::google::protobuf::uint8* target) const {
  // @@protoc_insertion_point(serialize_to_array_start:Protobuf.FHE_Ctxt)
  // required string content = 1;
  if (has_content()) {
    ::google::protobuf::internal::WireFormat::VerifyUTF8StringNamedField(
      this->content().data(), this->content().length(),
      ::google::protobuf::internal::WireFormat::SERIALIZE,
      "content");
    target =
      ::google::protobuf::internal::WireFormatLite::WriteStringToArray(
        1, this->content(), target);
  }

  if (!unknown_fields().empty()) {
    target = ::google::protobuf::internal::WireFormat::SerializeUnknownFieldsToArray(
        unknown_fields(), target);
  }
  // @@protoc_insertion_point(serialize_to_array_end:Protobuf.FHE_Ctxt)
  return target;
}

int FHE_Ctxt::ByteSize() const {
  int total_size = 0;

  if (_has_bits_[0 / 32] & (0xffu << (0 % 32))) {
    // required string content = 1;
    if (has_content()) {
      total_size += 1 +
        ::google::protobuf::internal::WireFormatLite::StringSize(
          this->content());
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

void FHE_Ctxt::MergeFrom(const ::google::protobuf::Message& from) {
  GOOGLE_CHECK_NE(&from, this);
  const FHE_Ctxt* source =
    ::google::protobuf::internal::dynamic_cast_if_available<const FHE_Ctxt*>(
      &from);
  if (source == NULL) {
    ::google::protobuf::internal::ReflectionOps::Merge(from, this);
  } else {
    MergeFrom(*source);
  }
}

void FHE_Ctxt::MergeFrom(const FHE_Ctxt& from) {
  GOOGLE_CHECK_NE(&from, this);
  if (from._has_bits_[0 / 32] & (0xffu << (0 % 32))) {
    if (from.has_content()) {
      set_content(from.content());
    }
  }
  mutable_unknown_fields()->MergeFrom(from.unknown_fields());
}

void FHE_Ctxt::CopyFrom(const ::google::protobuf::Message& from) {
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

void FHE_Ctxt::CopyFrom(const FHE_Ctxt& from) {
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

bool FHE_Ctxt::IsInitialized() const {
  if ((_has_bits_[0] & 0x00000001) != 0x00000001) return false;

  return true;
}

void FHE_Ctxt::Swap(FHE_Ctxt* other) {
  if (other != this) {
    std::swap(content_, other->content_);
    std::swap(_has_bits_[0], other->_has_bits_[0]);
    _unknown_fields_.Swap(&other->_unknown_fields_);
    std::swap(_cached_size_, other->_cached_size_);
  }
}

::google::protobuf::Metadata FHE_Ctxt::GetMetadata() const {
  protobuf_AssignDescriptorsOnce();
  ::google::protobuf::Metadata metadata;
  metadata.descriptor = FHE_Ctxt_descriptor_;
  metadata.reflection = FHE_Ctxt_reflection_;
  return metadata;
}


// @@protoc_insertion_point(namespace_scope)

}  // namespace Protobuf

// @@protoc_insertion_point(global_scope)
