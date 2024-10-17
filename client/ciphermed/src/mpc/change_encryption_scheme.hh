

#pragma once

#include <gmpxx.h>

#include <crypto/gm.hh>
#include <crypto/paillier.hh>

#include <FHE.h>
#include <EncryptedArray.h>

#include <vector>

using namespace std;

class Change_ES_FHE_to_GM_A {
public:
//    Change_ES_FHE_to_GM_A()

    mpz_class blind(const mpz_class &c, GM &gm, gmp_randstate_t state);
    Ctxt unblind(const Ctxt &c, const FHEPubKey& publicKey, const EncryptedArray &ea);
protected:
    bool coin_;
};

class Change_ES_FHE_to_GM_B {
    public:
    static Ctxt decrypt_encrypt(const mpz_class &c, GM_priv &gm, const FHEPubKey &publicKey, const EncryptedArray &ea);
};



class Change_ES_FHE_to_GM_slots_A {
    public:
    //    Change_ES_FHE_to_GM_A()
    
    vector<mpz_class> blind(const vector<mpz_class> &c, GM &gm, gmp_randstate_t state, unsigned long n_slots);
    Ctxt unblind(const Ctxt &c, const FHEPubKey& publicKey, const EncryptedArray &ea);
    protected:
    vector<long> coins_;
};

class Change_ES_FHE_to_GM_slots_B {
    public:
    static Ctxt decrypt_encrypt(const vector<mpz_class> &c, GM_priv &gm, const FHEPubKey &publicKey, const EncryptedArray &ea);
};

//add by andy 2017
class Change_ES_FHE_to_Paillier_slots_B{
    public:
    static vector<mpz_class> decrypt_encrypt(const vector<Ctxt> &c, Paillier &paillier, const FHESecKey &secretKey, const EncryptedArray &ea);
};


class Change_ES_FHE_to_Paillier_slots_A{
	public:
        vector<Ctxt> blind(const vector<Ctxt> &c,const FHEPubKey& publicKey, gmp_randstate_t state,const EncryptedArray &ea);
        vector<mpz_class> unblind(const vector<mpz_class>& c,Paillier &paillier);
        protected:
        vector<long> coins_;
};
//end add
