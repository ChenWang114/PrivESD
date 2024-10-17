#pragma once

#include <gmpxx.h>

#include <crypto/paillier.hh>
#include <crypto/gm.hh>

#include <boost/asio.hpp>
#include <net/message_io.hh>

#include <mpc/lsic.hh>
#include <mpc/private_comparison.hh>
#include <mpc/garbled_comparison.hh>
#include <mpc/rev_enc_comparison.hh>
#include <mpc/enc_comparison.hh>
#include <mpc/linear_enc_argmax.hh>
#include <mpc/tree_enc_argmax.hh>

#include <math/util_gmp_rand.h>

#include <FHE.h>
#include <EncryptedArray.h>

#include <functional>

using boost::asio::ip::tcp;


void exec_comparison_protocol_A(tcp::socket &socket, Comparison_protocol_A *comparator, unsigned int n_threads = 2);
void exec_lsic_A(tcp::socket &socket, LSIC_A *lsic);
void exec_priv_compare_A(tcp::socket &socket, Compare_A *comparator, unsigned int n_threads);
void exec_garbled_compare_A(tcp::socket &socket, GC_Compare_A *comparator);

void exec_comparison_protocol_B(tcp::socket &socket, Comparison_protocol_B *comparator, unsigned int n_threads = 2);
void exec_lsic_B(tcp::socket &socket, LSIC_B *lsic);
void exec_priv_compare_B(tcp::socket &socket, Compare_B *comparator, unsigned int n_threads = 2);
void exec_garbled_compare_B(tcp::socket &socket, GC_Compare_B *comparator);

void exec_enc_comparison_owner(tcp::socket &socket, EncCompare_Owner &owner, unsigned int lambda, bool decrypt_result, unsigned int n_threads = 2);
void exec_enc_comparison_helper(tcp::socket &socket, EncCompare_Helper &helper, bool decrypt_result, unsigned int n_threads = 2);

void exec_rev_enc_comparison_owner(tcp::socket &socket, Rev_EncCompare_Owner &owner, unsigned int lambda, bool decrypt_result, unsigned int n_threads = 2);
void exec_rev_enc_comparison_helper(tcp::socket &socket, Rev_EncCompare_Helper &helper, bool decrypt_result, unsigned int n_threads = 2);

void multiple_exec_enc_comparison_owner(tcp::socket &socket, vector<EncCompare_Owner*> &owners, unsigned int lambda, bool decrypt_result, unsigned int n_threads);
void multiple_exec_enc_comparison_helper(tcp::socket &socket, vector<EncCompare_Helper*> &helpers, bool decrypt_result, unsigned int n_threads = 2);

void multiple_exec_rev_enc_comparison_owner(tcp::socket &socket, vector<Rev_EncCompare_Owner*> &owners, unsigned int lambda, bool decrypt_result, unsigned int n_threads);
void multiple_exec_rev_enc_comparison_helper(tcp::socket &socket, vector<Rev_EncCompare_Helper*> &helpers, bool decrypt_result, unsigned int n_threads);

void exec_linear_enc_argmax(tcp::socket &socket, Linear_EncArgmax_Owner &owner, function<Comparison_protocol_A*()> comparator_creator, unsigned int lambda, unsigned int n_threads = 2);
void exec_linear_enc_argmax(tcp::socket &socket, Linear_EncArgmax_Helper &helper, function<Comparison_protocol_B*()> comparator_creator, unsigned int n_threads = 2);

void exec_tree_enc_argmax(tcp::socket &socket, Tree_EncArgmax_Owner &owner, function<Comparison_protocol_A*()> comparator_creator, unsigned int lambda, unsigned int n_threads = 2);
void exec_tree_enc_argmax(tcp::socket &socket, Tree_EncArgmax_Helper &helper, function<Comparison_protocol_B*()> comparator_creator, unsigned int n_threads = 2);

Ctxt exec_change_encryption_scheme_slots(tcp::socket &socket, const vector<mpz_class> &c_gm, GM &gm, const FHEPubKey& publicKey, const EncryptedArray &ea, gmp_randstate_t randstate);
void exec_change_encryption_scheme_slots_helper(tcp::socket &socket, GM_priv &gm, const FHEPubKey &publicKey, const EncryptedArray &ea);

/*add by andy 2017*/
vector<mpz_class> exec_change_encryption_scheme_slots(tcp::socket &socket,const vector<Ctxt> &c_fhe,Paillier &p_k,const FHEPubKey& publicKey, const EncryptedArray &ea, gmp_randstate_t randstate);
void exes_change_encryption_scheme_slots_helper(tcp::socket &socket,Paillier &p_k,const FHEPubKey& publicKey, const FHESecKey &secretKey,const EncryptedArray &ea,Paillier_priv_fast& pp);
/**end add*/

//add by andy 2018
void exes_Encrypted_LSB_helper(tcp::socket &socket,Paillier_priv_fast &pp);
void exes_SVR_helper(tcp::socket &socket,Paillier_priv_fast &pp);
void exes_SBD_helper(tcp::socket &socket,Paillier_priv_fast &pp);
void exes_SM_helper(tcp::socket &socket,Paillier_priv_fast &pp,mpz_class N);
void exes_SBOR_helper(tcp::socket &socket,Paillier_priv_fast &pp,mpz_class N);

void exes_FHE_Calc(tcp::socket &socket,long op1,long op2,const FHEPubKey& fhe_pk,const FHESecKey& fhe_sk,const EncryptedArray ea);
void exes_GETMINn_Right_helper(tcp::socket &socket,Paillier_priv_fast &pp);
void exes_calcDis_helper(tcp::socket &socket,int train_num,vector<vector<Ctxt>> theStack,const FHEPubKey& publicKey, const FHESecKey& secretKey,const EncryptedArray ea);
//add end


mpz_class exec_compute_dot_product(tcp::socket &socket, const vector<mpz_class> &x, Paillier &p);
void exec_help_compute_dot_product(tcp::socket &socket, const vector<mpz_class> &y, Paillier_priv &pp, bool encrypted_input);
