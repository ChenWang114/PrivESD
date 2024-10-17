// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: test_requests.proto

#ifndef PROTOBUF_test_5frequests_2eproto__INCLUDED
#define PROTOBUF_test_5frequests_2eproto__INCLUDED

#include <string>

#include <google/protobuf/stubs/common.h>

#if GOOGLE_PROTOBUF_VERSION < 2006000
#error This file was generated by a newer version of protoc which is
#error incompatible with your Protocol Buffer headers.  Please update
#error your headers.
#endif
#if 2006001 < GOOGLE_PROTOBUF_MIN_PROTOC_VERSION
#error This file was generated by an older version of protoc which is
#error incompatible with your Protocol Buffer headers.  Please
#error regenerate this file with a newer version of protoc.
#endif

#include <google/protobuf/generated_message_util.h>
#include <google/protobuf/message.h>
#include <google/protobuf/repeated_field.h>
#include <google/protobuf/extension_set.h>
#include <google/protobuf/generated_enum_reflection.h>
#include <google/protobuf/unknown_field_set.h>
// @@protoc_insertion_point(includes)

// Internal implementation detail -- do not call these.
void  protobuf_AddDesc_test_5frequests_2eproto();
void protobuf_AssignDesc_test_5frequests_2eproto();
void protobuf_ShutdownFile_test_5frequests_2eproto();

class Test_Request;

enum Test_Request_Request_Type {
  Test_Request_Request_Type_TEST_LSIC = 0,
  Test_Request_Request_Type_TEST_COMPARE = 1,
  Test_Request_Request_Type_TEST_GARBLED_COMPARE = 2,
  Test_Request_Request_Type_TEST_ENC_COMPARE = 3,
  Test_Request_Request_Type_TEST_REV_ENC_COMPARE = 4,
  Test_Request_Request_Type_TEST_LINEAR_ENC_ARGMAX = 5,
  Test_Request_Request_Type_TEST_FHE = 6,
  Test_Request_Request_Type_TEST_CHANGE_ES = 7,
  Test_Request_Request_Type_TEST_MULTIPLE_COMPARE = 8,
  Test_Request_Request_Type_TEST_TREE_ENC_ARGMAX = 9,
  Test_Request_Request_Type_TEST_OT = 10,
  Test_Request_Request_Type_DISCONNECT = 15
};
bool Test_Request_Request_Type_IsValid(int value);
const Test_Request_Request_Type Test_Request_Request_Type_Request_Type_MIN = Test_Request_Request_Type_TEST_LSIC;
const Test_Request_Request_Type Test_Request_Request_Type_Request_Type_MAX = Test_Request_Request_Type_DISCONNECT;
const int Test_Request_Request_Type_Request_Type_ARRAYSIZE = Test_Request_Request_Type_Request_Type_MAX + 1;

const ::google::protobuf::EnumDescriptor* Test_Request_Request_Type_descriptor();
inline const ::std::string& Test_Request_Request_Type_Name(Test_Request_Request_Type value) {
  return ::google::protobuf::internal::NameOfEnum(
    Test_Request_Request_Type_descriptor(), value);
}
inline bool Test_Request_Request_Type_Parse(
    const ::std::string& name, Test_Request_Request_Type* value) {
  return ::google::protobuf::internal::ParseNamedEnum<Test_Request_Request_Type>(
    Test_Request_Request_Type_descriptor(), name, value);
}
// ===================================================================

class Test_Request : public ::google::protobuf::Message {
 public:
  Test_Request();
  virtual ~Test_Request();

  Test_Request(const Test_Request& from);

  inline Test_Request& operator=(const Test_Request& from) {
    CopyFrom(from);
    return *this;
  }

  inline const ::google::protobuf::UnknownFieldSet& unknown_fields() const {
    return _unknown_fields_;
  }

  inline ::google::protobuf::UnknownFieldSet* mutable_unknown_fields() {
    return &_unknown_fields_;
  }

  static const ::google::protobuf::Descriptor* descriptor();
  static const Test_Request& default_instance();

  void Swap(Test_Request* other);

  // implements Message ----------------------------------------------

  Test_Request* New() const;
  void CopyFrom(const ::google::protobuf::Message& from);
  void MergeFrom(const ::google::protobuf::Message& from);
  void CopyFrom(const Test_Request& from);
  void MergeFrom(const Test_Request& from);
  void Clear();
  bool IsInitialized() const;

  int ByteSize() const;
  bool MergePartialFromCodedStream(
      ::google::protobuf::io::CodedInputStream* input);
  void SerializeWithCachedSizes(
      ::google::protobuf::io::CodedOutputStream* output) const;
  ::google::protobuf::uint8* SerializeWithCachedSizesToArray(::google::protobuf::uint8* output) const;
  int GetCachedSize() const { return _cached_size_; }
  private:
  void SharedCtor();
  void SharedDtor();
  void SetCachedSize(int size) const;
  public:
  ::google::protobuf::Metadata GetMetadata() const;

  // nested types ----------------------------------------------------

  typedef Test_Request_Request_Type Request_Type;
  static const Request_Type TEST_LSIC = Test_Request_Request_Type_TEST_LSIC;
  static const Request_Type TEST_COMPARE = Test_Request_Request_Type_TEST_COMPARE;
  static const Request_Type TEST_GARBLED_COMPARE = Test_Request_Request_Type_TEST_GARBLED_COMPARE;
  static const Request_Type TEST_ENC_COMPARE = Test_Request_Request_Type_TEST_ENC_COMPARE;
  static const Request_Type TEST_REV_ENC_COMPARE = Test_Request_Request_Type_TEST_REV_ENC_COMPARE;
  static const Request_Type TEST_LINEAR_ENC_ARGMAX = Test_Request_Request_Type_TEST_LINEAR_ENC_ARGMAX;
  static const Request_Type TEST_FHE = Test_Request_Request_Type_TEST_FHE;
  static const Request_Type TEST_CHANGE_ES = Test_Request_Request_Type_TEST_CHANGE_ES;
  static const Request_Type TEST_MULTIPLE_COMPARE = Test_Request_Request_Type_TEST_MULTIPLE_COMPARE;
  static const Request_Type TEST_TREE_ENC_ARGMAX = Test_Request_Request_Type_TEST_TREE_ENC_ARGMAX;
  static const Request_Type TEST_OT = Test_Request_Request_Type_TEST_OT;
  static const Request_Type DISCONNECT = Test_Request_Request_Type_DISCONNECT;
  static inline bool Request_Type_IsValid(int value) {
    return Test_Request_Request_Type_IsValid(value);
  }
  static const Request_Type Request_Type_MIN =
    Test_Request_Request_Type_Request_Type_MIN;
  static const Request_Type Request_Type_MAX =
    Test_Request_Request_Type_Request_Type_MAX;
  static const int Request_Type_ARRAYSIZE =
    Test_Request_Request_Type_Request_Type_ARRAYSIZE;
  static inline const ::google::protobuf::EnumDescriptor*
  Request_Type_descriptor() {
    return Test_Request_Request_Type_descriptor();
  }
  static inline const ::std::string& Request_Type_Name(Request_Type value) {
    return Test_Request_Request_Type_Name(value);
  }
  static inline bool Request_Type_Parse(const ::std::string& name,
      Request_Type* value) {
    return Test_Request_Request_Type_Parse(name, value);
  }

  // accessors -------------------------------------------------------

  // required .Test_Request.Request_Type type = 1;
  inline bool has_type() const;
  inline void clear_type();
  static const int kTypeFieldNumber = 1;
  inline ::Test_Request_Request_Type type() const;
  inline void set_type(::Test_Request_Request_Type value);

  // optional uint32 bit_size = 2;
  inline bool has_bit_size() const;
  inline void clear_bit_size();
  static const int kBitSizeFieldNumber = 2;
  inline ::google::protobuf::uint32 bit_size() const;
  inline void set_bit_size(::google::protobuf::uint32 value);

  // optional uint32 iterations = 3;
  inline bool has_iterations() const;
  inline void clear_iterations();
  static const int kIterationsFieldNumber = 3;
  inline ::google::protobuf::uint32 iterations() const;
  inline void set_iterations(::google::protobuf::uint32 value);

  // optional uint32 comparison_protocol = 4;
  inline bool has_comparison_protocol() const;
  inline void clear_comparison_protocol();
  static const int kComparisonProtocolFieldNumber = 4;
  inline ::google::protobuf::uint32 comparison_protocol() const;
  inline void set_comparison_protocol(::google::protobuf::uint32 value);

  // optional uint32 argmax_elements = 5;
  inline bool has_argmax_elements() const;
  inline void clear_argmax_elements();
  static const int kArgmaxElementsFieldNumber = 5;
  inline ::google::protobuf::uint32 argmax_elements() const;
  inline void set_argmax_elements(::google::protobuf::uint32 value);

  // @@protoc_insertion_point(class_scope:Test_Request)
 private:
  inline void set_has_type();
  inline void clear_has_type();
  inline void set_has_bit_size();
  inline void clear_has_bit_size();
  inline void set_has_iterations();
  inline void clear_has_iterations();
  inline void set_has_comparison_protocol();
  inline void clear_has_comparison_protocol();
  inline void set_has_argmax_elements();
  inline void clear_has_argmax_elements();

  ::google::protobuf::UnknownFieldSet _unknown_fields_;

  ::google::protobuf::uint32 _has_bits_[1];
  mutable int _cached_size_;
  int type_;
  ::google::protobuf::uint32 bit_size_;
  ::google::protobuf::uint32 iterations_;
  ::google::protobuf::uint32 comparison_protocol_;
  ::google::protobuf::uint32 argmax_elements_;
  friend void  protobuf_AddDesc_test_5frequests_2eproto();
  friend void protobuf_AssignDesc_test_5frequests_2eproto();
  friend void protobuf_ShutdownFile_test_5frequests_2eproto();

  void InitAsDefaultInstance();
  static Test_Request* default_instance_;
};
// ===================================================================


// ===================================================================

// Test_Request

// required .Test_Request.Request_Type type = 1;
inline bool Test_Request::has_type() const {
  return (_has_bits_[0] & 0x00000001u) != 0;
}
inline void Test_Request::set_has_type() {
  _has_bits_[0] |= 0x00000001u;
}
inline void Test_Request::clear_has_type() {
  _has_bits_[0] &= ~0x00000001u;
}
inline void Test_Request::clear_type() {
  type_ = 0;
  clear_has_type();
}
inline ::Test_Request_Request_Type Test_Request::type() const {
  // @@protoc_insertion_point(field_get:Test_Request.type)
  return static_cast< ::Test_Request_Request_Type >(type_);
}
inline void Test_Request::set_type(::Test_Request_Request_Type value) {
  assert(::Test_Request_Request_Type_IsValid(value));
  set_has_type();
  type_ = value;
  // @@protoc_insertion_point(field_set:Test_Request.type)
}

// optional uint32 bit_size = 2;
inline bool Test_Request::has_bit_size() const {
  return (_has_bits_[0] & 0x00000002u) != 0;
}
inline void Test_Request::set_has_bit_size() {
  _has_bits_[0] |= 0x00000002u;
}
inline void Test_Request::clear_has_bit_size() {
  _has_bits_[0] &= ~0x00000002u;
}
inline void Test_Request::clear_bit_size() {
  bit_size_ = 0u;
  clear_has_bit_size();
}
inline ::google::protobuf::uint32 Test_Request::bit_size() const {
  // @@protoc_insertion_point(field_get:Test_Request.bit_size)
  return bit_size_;
}
inline void Test_Request::set_bit_size(::google::protobuf::uint32 value) {
  set_has_bit_size();
  bit_size_ = value;
  // @@protoc_insertion_point(field_set:Test_Request.bit_size)
}

// optional uint32 iterations = 3;
inline bool Test_Request::has_iterations() const {
  return (_has_bits_[0] & 0x00000004u) != 0;
}
inline void Test_Request::set_has_iterations() {
  _has_bits_[0] |= 0x00000004u;
}
inline void Test_Request::clear_has_iterations() {
  _has_bits_[0] &= ~0x00000004u;
}
inline void Test_Request::clear_iterations() {
  iterations_ = 0u;
  clear_has_iterations();
}
inline ::google::protobuf::uint32 Test_Request::iterations() const {
  // @@protoc_insertion_point(field_get:Test_Request.iterations)
  return iterations_;
}
inline void Test_Request::set_iterations(::google::protobuf::uint32 value) {
  set_has_iterations();
  iterations_ = value;
  // @@protoc_insertion_point(field_set:Test_Request.iterations)
}

// optional uint32 comparison_protocol = 4;
inline bool Test_Request::has_comparison_protocol() const {
  return (_has_bits_[0] & 0x00000008u) != 0;
}
inline void Test_Request::set_has_comparison_protocol() {
  _has_bits_[0] |= 0x00000008u;
}
inline void Test_Request::clear_has_comparison_protocol() {
  _has_bits_[0] &= ~0x00000008u;
}
inline void Test_Request::clear_comparison_protocol() {
  comparison_protocol_ = 0u;
  clear_has_comparison_protocol();
}
inline ::google::protobuf::uint32 Test_Request::comparison_protocol() const {
  // @@protoc_insertion_point(field_get:Test_Request.comparison_protocol)
  return comparison_protocol_;
}
inline void Test_Request::set_comparison_protocol(::google::protobuf::uint32 value) {
  set_has_comparison_protocol();
  comparison_protocol_ = value;
  // @@protoc_insertion_point(field_set:Test_Request.comparison_protocol)
}

// optional uint32 argmax_elements = 5;
inline bool Test_Request::has_argmax_elements() const {
  return (_has_bits_[0] & 0x00000010u) != 0;
}
inline void Test_Request::set_has_argmax_elements() {
  _has_bits_[0] |= 0x00000010u;
}
inline void Test_Request::clear_has_argmax_elements() {
  _has_bits_[0] &= ~0x00000010u;
}
inline void Test_Request::clear_argmax_elements() {
  argmax_elements_ = 0u;
  clear_has_argmax_elements();
}
inline ::google::protobuf::uint32 Test_Request::argmax_elements() const {
  // @@protoc_insertion_point(field_get:Test_Request.argmax_elements)
  return argmax_elements_;
}
inline void Test_Request::set_argmax_elements(::google::protobuf::uint32 value) {
  set_has_argmax_elements();
  argmax_elements_ = value;
  // @@protoc_insertion_point(field_set:Test_Request.argmax_elements)
}


// @@protoc_insertion_point(namespace_scope)

#ifndef SWIG
namespace google {
namespace protobuf {

template <> struct is_proto_enum< ::Test_Request_Request_Type> : ::google::protobuf::internal::true_type {};
template <>
inline const EnumDescriptor* GetEnumDescriptor< ::Test_Request_Request_Type>() {
  return ::Test_Request_Request_Type_descriptor();
}

}  // namespace google
}  // namespace protobuf
#endif  // SWIG

// @@protoc_insertion_point(global_scope)

#endif  // PROTOBUF_test_5frequests_2eproto__INCLUDED
