

#include <mpc/change_encryption_scheme.hh>
#include <NTL/ZZX.h>

#include <algorithm>

using namespace NTL;

mpz_class Change_ES_FHE_to_GM_A::blind(const mpz_class &c, GM &gm, gmp_randstate_t state)
{
    coin_ = gmp_urandomb_ui(state,1);
    
    if (coin_) {
        return gm.neg(c);
    }
    
    return c;
}

Ctxt Change_ES_FHE_to_GM_A::unblind(const Ctxt &c, const FHEPubKey& publicKey, const EncryptedArray &ea)
{
    if (coin_) {
        Ctxt d(c);
        
        NewPlaintextArray array(ea);
        //array.encode(1);
        encode(ea,array,1);
        ZZX poly;
        ea.encode(poly,array);
        
        d.addConstant(poly);
        
        return d;
    }
    
    return c;
}


Ctxt Change_ES_FHE_to_GM_B::decrypt_encrypt(const mpz_class &c, GM_priv &gm, const FHEPubKey &publicKey, const EncryptedArray &ea)
{
    bool b = gm.decrypt(c);
    NewPlaintextArray array(ea);
    //array.encode(b);
    encode(ea,array,b);
   
    Ctxt c0(publicKey);
    ea.encrypt(c0, publicKey, array);

    return c0;
}



vector<mpz_class> Change_ES_FHE_to_GM_slots_A::blind(const vector<mpz_class> &c, GM &gm, gmp_randstate_t state, unsigned long n_slots)
{
    size_t n = std::min<size_t>(c.size(),n_slots);
    vector<mpz_class> rand_c(n_slots);
    coins_ = vector<long>(n);
    
    for (size_t i = 0; i < n; i++) {
        coins_[i] = gmp_urandomb_ui(state,1);
        
        if (coins_[i]) {
            rand_c[i] = gm.neg(c[i]);
        }else{
            rand_c[i] = c[i];
        }
    }
    
    return rand_c;
}

Ctxt Change_ES_FHE_to_GM_slots_A::unblind(const Ctxt &c, const FHEPubKey& publicKey, const EncryptedArray &ea)
{
    Ctxt d(c);
    
    NewPlaintextArray array(ea);
    //array.encode(coins_);
    encode(ea,array,coins_);
    ZZX poly;
    ea.encode(poly,array);
    
    d.addConstant(poly);
    
    return d;
}

Ctxt Change_ES_FHE_to_GM_slots_B::decrypt_encrypt(const vector<mpz_class> &c, GM_priv &gm, const FHEPubKey &publicKey, const EncryptedArray &ea)
{
    vector<long> v(c.size());
    
    for (size_t i = 0; i < c.size(); i++) {
        v[i] = gm.decrypt(c[i]);
    }
    
    NewPlaintextArray array(ea);
    //array.encode(v);
    encode(ea,array,v);
    
    Ctxt c0(publicKey);
    ea.encrypt(c0, publicKey, array);
    
    return c0;

}



/**add by andy 2017*/
vector<mpz_class> Change_ES_FHE_to_Paillier_slots_B::decrypt_encrypt(const vector<Ctxt> &c, Paillier &paillier, const FHESecKey &secretKey, const EncryptedArray &ea)
{
       vector<long>v;
       vector<mpz_class>p_vec;
       for(size_t i=0;i<c.size();i++)
	{
	       ea.decrypt(c[i], secretKey, v);
	       //cout<<"v[0]"<<v[0]<<endl;
	       mpz_class p = paillier.encrypt(v[0]);
               p_vec.push_back(p);
	}
       return p_vec;
}

static Ctxt ctxt_neg(Ctxt c, const EncryptedArray &ea)
{
    Ctxt c_neg(c);
    NewPlaintextArray pa(ea);
    //pa.encode(1);
    encode(ea,pa,1);

    ZZX one;
    ea.encode(one, pa);
    
    c_neg.addConstant(one);
    
    return c_neg;
}

vector<Ctxt> Change_ES_FHE_to_Paillier_slots_A::blind(const vector<Ctxt> &c,const FHEPubKey& publicKey, gmp_randstate_t state,const EncryptedArray &ea)
{
      vector<Ctxt> rand_c;
      coins_ = vector<long>(c.size());
      for(size_t i=0;i<c.size();i++){
          coins_[i] = gmp_urandomb_ui(state,1);
          if(coins_[i]){
	     rand_c.push_back(ctxt_neg(c[i],ea));
          }else{
             rand_c.push_back(c[i]);
          }
      } 
      return rand_c;  
}

vector<mpz_class> Change_ES_FHE_to_Paillier_slots_A::unblind(const vector<mpz_class>& c,Paillier &paillier)
{
    vector<mpz_class> c_paillier(c.size());
    for(size_t i=0;i<c.size();i++)
    {
         if(coins_[i]){
            mpz_class a = paillier.encrypt(coins_[i]);
	    c_paillier[i] = paillier.sub(c[i],a);		
	 }else{
            c_paillier[i] = c[i];
	 }
    }
    return c_paillier;
}
/**end add*/
