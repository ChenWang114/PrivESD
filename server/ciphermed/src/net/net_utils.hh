#pragma once

#include <iostream>
#include <vector>

#include <boost/asio.hpp>

#include <mpc/lsic.hh>
#include <gmpxx.h>

#include <FHE.h>

#include <xmmintrin.h>
#include <emmintrin.h>
#include <smmintrin.h>

using namespace std;

ostream& operator<<(ostream& out, const LSIC_Packet_A& p);
ostream& operator<<(ostream& out, const LSIC_Packet_B& p);

istream& operator>>(istream& in, LSIC_Packet_A& p);
istream& operator>>(istream& in, LSIC_Packet_B& p);

ostream& operator<<(ostream& out, const vector<mpz_class> &v);
// will only read the v.size() elements of the stream
istream& operator>>(istream& in, vector<mpz_class> &v);

istream& parseInt(istream& in, mpz_class &i, int base);


void sendIntToSocket(boost::asio::ip::tcp::socket &socket, const mpz_class& m);
mpz_class readIntFromSocket(boost::asio::ip::tcp::socket &socket);


void send_int_array_to_socket(boost::asio::ip::tcp::socket &socket, const vector<mpz_class>& m);
vector<mpz_class> read_int_array_from_socket(boost::asio::ip::tcp::socket &socket);


void send_fhe_ctxt_to_socket(boost::asio::ip::tcp::socket &socket, const Ctxt &c);
Ctxt read_fhe_ctxt_from_socket(boost::asio::ip::tcp::socket &socket, const FHEPubKey &pubkey);


void read_byte_string_from_socket(boost::asio::ip::tcp::socket &socket, unsigned char *buffer, size_t byte_count);
void read_byte_string_from_socket(boost::asio::ip::tcp::socket &socket, char *buffer, size_t byte_count);
void write_byte_string_to_socket(boost::asio::ip::tcp::socket &socket, unsigned char *buffer, size_t byte_count);
void write_byte_string_to_socket(boost::asio::ip::tcp::socket &socket, char *buffer, size_t byte_count);

__m128i read_block_from_socket(boost::asio::ip::tcp::socket &socket);
void write_block_to_socket(__m128i block, boost::asio::ip::tcp::socket &socket);