// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: lsic_messages.proto

#ifndef PROTOBUF_lsic_5fmessages_2eproto__INCLUDED
#define PROTOBUF_lsic_5fmessages_2eproto__INCLUDED

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
#include <google/protobuf/unknown_field_set.h>
#include "bigint.pb.h"
// @@protoc_insertion_point(includes)

namespace Protobuf {

// Internal implementation detail -- do not call these.
void  protobuf_AddDesc_lsic_5fmessages_2eproto();
void protobuf_AssignDesc_lsic_5fmessages_2eproto();
void protobuf_ShutdownFile_lsic_5fmessages_2eproto();

class SOCKET_READY_Message;
class LSIC_A_Message;
class LSIC_B_Message;
class Enc_Compare_Setup_Message;

// ===================================================================

class SOCKET_READY_Message : public ::google::protobuf::Message {
 public:
  SOCKET_READY_Message();
  virtual ~SOCKET_READY_Message();

  SOCKET_READY_Message(const SOCKET_READY_Message& from);

  inline SOCKET_READY_Message& operator=(const SOCKET_READY_Message& from) {
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
  static const SOCKET_READY_Message& default_instance();

  void Swap(SOCKET_READY_Message* other);

  // implements Message ----------------------------------------------

  SOCKET_READY_Message* New() const;
  void CopyFrom(const ::google::protobuf::Message& from);
  void MergeFrom(const ::google::protobuf::Message& from);
  void CopyFrom(const SOCKET_READY_Message& from);
  void MergeFrom(const SOCKET_READY_Message& from);
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

  // accessors -------------------------------------------------------

  // @@protoc_insertion_point(class_scope:Protobuf.SOCKET_READY_Message)
 private:

  ::google::protobuf::UnknownFieldSet _unknown_fields_;

  ::google::protobuf::uint32 _has_bits_[1];
  mutable int _cached_size_;
  friend void  protobuf_AddDesc_lsic_5fmessages_2eproto();
  friend void protobuf_AssignDesc_lsic_5fmessages_2eproto();
  friend void protobuf_ShutdownFile_lsic_5fmessages_2eproto();

  void InitAsDefaultInstance();
  static SOCKET_READY_Message* default_instance_;
};
// -------------------------------------------------------------------

class LSIC_A_Message : public ::google::protobuf::Message {
 public:
  LSIC_A_Message();
  virtual ~LSIC_A_Message();

  LSIC_A_Message(const LSIC_A_Message& from);

  inline LSIC_A_Message& operator=(const LSIC_A_Message& from) {
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
  static const LSIC_A_Message& default_instance();

  void Swap(LSIC_A_Message* other);

  // implements Message ----------------------------------------------

  LSIC_A_Message* New() const;
  void CopyFrom(const ::google::protobuf::Message& from);
  void MergeFrom(const ::google::protobuf::Message& from);
  void CopyFrom(const LSIC_A_Message& from);
  void MergeFrom(const LSIC_A_Message& from);
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

  // accessors -------------------------------------------------------

  // required uint32 index = 1;
  inline bool has_index() const;
  inline void clear_index();
  static const int kIndexFieldNumber = 1;
  inline ::google::protobuf::uint32 index() const;
  inline void set_index(::google::protobuf::uint32 value);

  // required .Protobuf.BigInt tau = 2;
  inline bool has_tau() const;
  inline void clear_tau();
  static const int kTauFieldNumber = 2;
  inline const ::Protobuf::BigInt& tau() const;
  inline ::Protobuf::BigInt* mutable_tau();
  inline ::Protobuf::BigInt* release_tau();
  inline void set_allocated_tau(::Protobuf::BigInt* tau);

  // @@protoc_insertion_point(class_scope:Protobuf.LSIC_A_Message)
 private:
  inline void set_has_index();
  inline void clear_has_index();
  inline void set_has_tau();
  inline void clear_has_tau();

  ::google::protobuf::UnknownFieldSet _unknown_fields_;

  ::google::protobuf::uint32 _has_bits_[1];
  mutable int _cached_size_;
  ::Protobuf::BigInt* tau_;
  ::google::protobuf::uint32 index_;
  friend void  protobuf_AddDesc_lsic_5fmessages_2eproto();
  friend void protobuf_AssignDesc_lsic_5fmessages_2eproto();
  friend void protobuf_ShutdownFile_lsic_5fmessages_2eproto();

  void InitAsDefaultInstance();
  static LSIC_A_Message* default_instance_;
};
// -------------------------------------------------------------------

class LSIC_B_Message : public ::google::protobuf::Message {
 public:
  LSIC_B_Message();
  virtual ~LSIC_B_Message();

  LSIC_B_Message(const LSIC_B_Message& from);

  inline LSIC_B_Message& operator=(const LSIC_B_Message& from) {
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
  static const LSIC_B_Message& default_instance();

  void Swap(LSIC_B_Message* other);

  // implements Message ----------------------------------------------

  LSIC_B_Message* New() const;
  void CopyFrom(const ::google::protobuf::Message& from);
  void MergeFrom(const ::google::protobuf::Message& from);
  void CopyFrom(const LSIC_B_Message& from);
  void MergeFrom(const LSIC_B_Message& from);
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

  // accessors -------------------------------------------------------

  // required uint32 index = 1;
  inline bool has_index() const;
  inline void clear_index();
  static const int kIndexFieldNumber = 1;
  inline ::google::protobuf::uint32 index() const;
  inline void set_index(::google::protobuf::uint32 value);

  // required .Protobuf.BigInt tb = 2;
  inline bool has_tb() const;
  inline void clear_tb();
  static const int kTbFieldNumber = 2;
  inline const ::Protobuf::BigInt& tb() const;
  inline ::Protobuf::BigInt* mutable_tb();
  inline ::Protobuf::BigInt* release_tb();
  inline void set_allocated_tb(::Protobuf::BigInt* tb);

  // required .Protobuf.BigInt bi = 3;
  inline bool has_bi() const;
  inline void clear_bi();
  static const int kBiFieldNumber = 3;
  inline const ::Protobuf::BigInt& bi() const;
  inline ::Protobuf::BigInt* mutable_bi();
  inline ::Protobuf::BigInt* release_bi();
  inline void set_allocated_bi(::Protobuf::BigInt* bi);

  // @@protoc_insertion_point(class_scope:Protobuf.LSIC_B_Message)
 private:
  inline void set_has_index();
  inline void clear_has_index();
  inline void set_has_tb();
  inline void clear_has_tb();
  inline void set_has_bi();
  inline void clear_has_bi();

  ::google::protobuf::UnknownFieldSet _unknown_fields_;

  ::google::protobuf::uint32 _has_bits_[1];
  mutable int _cached_size_;
  ::Protobuf::BigInt* tb_;
  ::Protobuf::BigInt* bi_;
  ::google::protobuf::uint32 index_;
  friend void  protobuf_AddDesc_lsic_5fmessages_2eproto();
  friend void protobuf_AssignDesc_lsic_5fmessages_2eproto();
  friend void protobuf_ShutdownFile_lsic_5fmessages_2eproto();

  void InitAsDefaultInstance();
  static LSIC_B_Message* default_instance_;
};
// -------------------------------------------------------------------

class Enc_Compare_Setup_Message : public ::google::protobuf::Message {
 public:
  Enc_Compare_Setup_Message();
  virtual ~Enc_Compare_Setup_Message();

  Enc_Compare_Setup_Message(const Enc_Compare_Setup_Message& from);

  inline Enc_Compare_Setup_Message& operator=(const Enc_Compare_Setup_Message& from) {
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
  static const Enc_Compare_Setup_Message& default_instance();

  void Swap(Enc_Compare_Setup_Message* other);

  // implements Message ----------------------------------------------

  Enc_Compare_Setup_Message* New() const;
  void CopyFrom(const ::google::protobuf::Message& from);
  void MergeFrom(const ::google::protobuf::Message& from);
  void CopyFrom(const Enc_Compare_Setup_Message& from);
  void MergeFrom(const Enc_Compare_Setup_Message& from);
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

  // accessors -------------------------------------------------------

  // optional uint32 bit_length = 1;
  inline bool has_bit_length() const;
  inline void clear_bit_length();
  static const int kBitLengthFieldNumber = 1;
  inline ::google::protobuf::uint32 bit_length() const;
  inline void set_bit_length(::google::protobuf::uint32 value);

  // required .Protobuf.BigInt c_z = 2;
  inline bool has_c_z() const;
  inline void clear_c_z();
  static const int kCZFieldNumber = 2;
  inline const ::Protobuf::BigInt& c_z() const;
  inline ::Protobuf::BigInt* mutable_c_z();
  inline ::Protobuf::BigInt* release_c_z();
  inline void set_allocated_c_z(::Protobuf::BigInt* c_z);

  // @@protoc_insertion_point(class_scope:Protobuf.Enc_Compare_Setup_Message)
 private:
  inline void set_has_bit_length();
  inline void clear_has_bit_length();
  inline void set_has_c_z();
  inline void clear_has_c_z();

  ::google::protobuf::UnknownFieldSet _unknown_fields_;

  ::google::protobuf::uint32 _has_bits_[1];
  mutable int _cached_size_;
  ::Protobuf::BigInt* c_z_;
  ::google::protobuf::uint32 bit_length_;
  friend void  protobuf_AddDesc_lsic_5fmessages_2eproto();
  friend void protobuf_AssignDesc_lsic_5fmessages_2eproto();
  friend void protobuf_ShutdownFile_lsic_5fmessages_2eproto();

  void InitAsDefaultInstance();
  static Enc_Compare_Setup_Message* default_instance_;
};
// ===================================================================


// ===================================================================

// SOCKET_READY_Message

// -------------------------------------------------------------------

// LSIC_A_Message

// required uint32 index = 1;
inline bool LSIC_A_Message::has_index() const {
  return (_has_bits_[0] & 0x00000001u) != 0;
}
inline void LSIC_A_Message::set_has_index() {
  _has_bits_[0] |= 0x00000001u;
}
inline void LSIC_A_Message::clear_has_index() {
  _has_bits_[0] &= ~0x00000001u;
}
inline void LSIC_A_Message::clear_index() {
  index_ = 0u;
  clear_has_index();
}
inline ::google::protobuf::uint32 LSIC_A_Message::index() const {
  // @@protoc_insertion_point(field_get:Protobuf.LSIC_A_Message.index)
  return index_;
}
inline void LSIC_A_Message::set_index(::google::protobuf::uint32 value) {
  set_has_index();
  index_ = value;
  // @@protoc_insertion_point(field_set:Protobuf.LSIC_A_Message.index)
}

// required .Protobuf.BigInt tau = 2;
inline bool LSIC_A_Message::has_tau() const {
  return (_has_bits_[0] & 0x00000002u) != 0;
}
inline void LSIC_A_Message::set_has_tau() {
  _has_bits_[0] |= 0x00000002u;
}
inline void LSIC_A_Message::clear_has_tau() {
  _has_bits_[0] &= ~0x00000002u;
}
inline void LSIC_A_Message::clear_tau() {
  if (tau_ != NULL) tau_->::Protobuf::BigInt::Clear();
  clear_has_tau();
}
inline const ::Protobuf::BigInt& LSIC_A_Message::tau() const {
  // @@protoc_insertion_point(field_get:Protobuf.LSIC_A_Message.tau)
  return tau_ != NULL ? *tau_ : *default_instance_->tau_;
}
inline ::Protobuf::BigInt* LSIC_A_Message::mutable_tau() {
  set_has_tau();
  if (tau_ == NULL) tau_ = new ::Protobuf::BigInt;
  // @@protoc_insertion_point(field_mutable:Protobuf.LSIC_A_Message.tau)
  return tau_;
}
inline ::Protobuf::BigInt* LSIC_A_Message::release_tau() {
  clear_has_tau();
  ::Protobuf::BigInt* temp = tau_;
  tau_ = NULL;
  return temp;
}
inline void LSIC_A_Message::set_allocated_tau(::Protobuf::BigInt* tau) {
  delete tau_;
  tau_ = tau;
  if (tau) {
    set_has_tau();
  } else {
    clear_has_tau();
  }
  // @@protoc_insertion_point(field_set_allocated:Protobuf.LSIC_A_Message.tau)
}

// -------------------------------------------------------------------

// LSIC_B_Message

// required uint32 index = 1;
inline bool LSIC_B_Message::has_index() const {
  return (_has_bits_[0] & 0x00000001u) != 0;
}
inline void LSIC_B_Message::set_has_index() {
  _has_bits_[0] |= 0x00000001u;
}
inline void LSIC_B_Message::clear_has_index() {
  _has_bits_[0] &= ~0x00000001u;
}
inline void LSIC_B_Message::clear_index() {
  index_ = 0u;
  clear_has_index();
}
inline ::google::protobuf::uint32 LSIC_B_Message::index() const {
  // @@protoc_insertion_point(field_get:Protobuf.LSIC_B_Message.index)
  return index_;
}
inline void LSIC_B_Message::set_index(::google::protobuf::uint32 value) {
  set_has_index();
  index_ = value;
  // @@protoc_insertion_point(field_set:Protobuf.LSIC_B_Message.index)
}

// required .Protobuf.BigInt tb = 2;
inline bool LSIC_B_Message::has_tb() const {
  return (_has_bits_[0] & 0x00000002u) != 0;
}
inline void LSIC_B_Message::set_has_tb() {
  _has_bits_[0] |= 0x00000002u;
}
inline void LSIC_B_Message::clear_has_tb() {
  _has_bits_[0] &= ~0x00000002u;
}
inline void LSIC_B_Message::clear_tb() {
  if (tb_ != NULL) tb_->::Protobuf::BigInt::Clear();
  clear_has_tb();
}
inline const ::Protobuf::BigInt& LSIC_B_Message::tb() const {
  // @@protoc_insertion_point(field_get:Protobuf.LSIC_B_Message.tb)
  return tb_ != NULL ? *tb_ : *default_instance_->tb_;
}
inline ::Protobuf::BigInt* LSIC_B_Message::mutable_tb() {
  set_has_tb();
  if (tb_ == NULL) tb_ = new ::Protobuf::BigInt;
  // @@protoc_insertion_point(field_mutable:Protobuf.LSIC_B_Message.tb)
  return tb_;
}
inline ::Protobuf::BigInt* LSIC_B_Message::release_tb() {
  clear_has_tb();
  ::Protobuf::BigInt* temp = tb_;
  tb_ = NULL;
  return temp;
}
inline void LSIC_B_Message::set_allocated_tb(::Protobuf::BigInt* tb) {
  delete tb_;
  tb_ = tb;
  if (tb) {
    set_has_tb();
  } else {
    clear_has_tb();
  }
  // @@protoc_insertion_point(field_set_allocated:Protobuf.LSIC_B_Message.tb)
}

// required .Protobuf.BigInt bi = 3;
inline bool LSIC_B_Message::has_bi() const {
  return (_has_bits_[0] & 0x00000004u) != 0;
}
inline void LSIC_B_Message::set_has_bi() {
  _has_bits_[0] |= 0x00000004u;
}
inline void LSIC_B_Message::clear_has_bi() {
  _has_bits_[0] &= ~0x00000004u;
}
inline void LSIC_B_Message::clear_bi() {
  if (bi_ != NULL) bi_->::Protobuf::BigInt::Clear();
  clear_has_bi();
}
inline const ::Protobuf::BigInt& LSIC_B_Message::bi() const {
  // @@protoc_insertion_point(field_get:Protobuf.LSIC_B_Message.bi)
  return bi_ != NULL ? *bi_ : *default_instance_->bi_;
}
inline ::Protobuf::BigInt* LSIC_B_Message::mutable_bi() {
  set_has_bi();
  if (bi_ == NULL) bi_ = new ::Protobuf::BigInt;
  // @@protoc_insertion_point(field_mutable:Protobuf.LSIC_B_Message.bi)
  return bi_;
}
inline ::Protobuf::BigInt* LSIC_B_Message::release_bi() {
  clear_has_bi();
  ::Protobuf::BigInt* temp = bi_;
  bi_ = NULL;
  return temp;
}
inline void LSIC_B_Message::set_allocated_bi(::Protobuf::BigInt* bi) {
  delete bi_;
  bi_ = bi;
  if (bi) {
    set_has_bi();
  } else {
    clear_has_bi();
  }
  // @@protoc_insertion_point(field_set_allocated:Protobuf.LSIC_B_Message.bi)
}

// -------------------------------------------------------------------

// Enc_Compare_Setup_Message

// optional uint32 bit_length = 1;
inline bool Enc_Compare_Setup_Message::has_bit_length() const {
  return (_has_bits_[0] & 0x00000001u) != 0;
}
inline void Enc_Compare_Setup_Message::set_has_bit_length() {
  _has_bits_[0] |= 0x00000001u;
}
inline void Enc_Compare_Setup_Message::clear_has_bit_length() {
  _has_bits_[0] &= ~0x00000001u;
}
inline void Enc_Compare_Setup_Message::clear_bit_length() {
  bit_length_ = 0u;
  clear_has_bit_length();
}
inline ::google::protobuf::uint32 Enc_Compare_Setup_Message::bit_length() const {
  // @@protoc_insertion_point(field_get:Protobuf.Enc_Compare_Setup_Message.bit_length)
  return bit_length_;
}
inline void Enc_Compare_Setup_Message::set_bit_length(::google::protobuf::uint32 value) {
  set_has_bit_length();
  bit_length_ = value;
  // @@protoc_insertion_point(field_set:Protobuf.Enc_Compare_Setup_Message.bit_length)
}

// required .Protobuf.BigInt c_z = 2;
inline bool Enc_Compare_Setup_Message::has_c_z() const {
  return (_has_bits_[0] & 0x00000002u) != 0;
}
inline void Enc_Compare_Setup_Message::set_has_c_z() {
  _has_bits_[0] |= 0x00000002u;
}
inline void Enc_Compare_Setup_Message::clear_has_c_z() {
  _has_bits_[0] &= ~0x00000002u;
}
inline void Enc_Compare_Setup_Message::clear_c_z() {
  if (c_z_ != NULL) c_z_->::Protobuf::BigInt::Clear();
  clear_has_c_z();
}
inline const ::Protobuf::BigInt& Enc_Compare_Setup_Message::c_z() const {
  // @@protoc_insertion_point(field_get:Protobuf.Enc_Compare_Setup_Message.c_z)
  return c_z_ != NULL ? *c_z_ : *default_instance_->c_z_;
}
inline ::Protobuf::BigInt* Enc_Compare_Setup_Message::mutable_c_z() {
  set_has_c_z();
  if (c_z_ == NULL) c_z_ = new ::Protobuf::BigInt;
  // @@protoc_insertion_point(field_mutable:Protobuf.Enc_Compare_Setup_Message.c_z)
  return c_z_;
}
inline ::Protobuf::BigInt* Enc_Compare_Setup_Message::release_c_z() {
  clear_has_c_z();
  ::Protobuf::BigInt* temp = c_z_;
  c_z_ = NULL;
  return temp;
}
inline void Enc_Compare_Setup_Message::set_allocated_c_z(::Protobuf::BigInt* c_z) {
  delete c_z_;
  c_z_ = c_z;
  if (c_z) {
    set_has_c_z();
  } else {
    clear_has_c_z();
  }
  // @@protoc_insertion_point(field_set_allocated:Protobuf.Enc_Compare_Setup_Message.c_z)
}


// @@protoc_insertion_point(namespace_scope)

}  // namespace Protobuf

#ifndef SWIG
namespace google {
namespace protobuf {


}  // namespace google
}  // namespace protobuf
#endif  // SWIG

// @@protoc_insertion_point(global_scope)

#endif  // PROTOBUF_lsic_5fmessages_2eproto__INCLUDED
