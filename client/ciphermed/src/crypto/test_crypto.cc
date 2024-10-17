

#include <assert.h>
#include <vector>
#include <crypto/paillier.hh>
#include <crypto/gm.hh>
#include <NTL/ZZ.h>
#include <gmpxx.h>
#include <math/util_gmp_rand.h>

#include <ctime>

#include<iostream>

#include <map>
#include <algorithm>


using namespace std;
using namespace NTL;

static void
test_paillier()
{
    cout << "Test Paillier ..." << flush;
    
    gmp_randstate_t randstate;
    gmp_randinit_default(randstate);
    gmp_randseed_ui(randstate,time(NULL));
    
    auto sk = Paillier_priv::keygen(randstate,600);
    Paillier_priv pp(sk,randstate);
    
    auto pk = pp.pubkey();
    mpz_class n = pk[0];
    Paillier p(pk,randstate);
    
    mpz_class pt0, pt1,m;
    mpz_urandomm(pt0.get_mpz_t(),randstate,n.get_mpz_t());
    mpz_urandomm(pt1.get_mpz_t(),randstate,n.get_mpz_t());
    mpz_urandomm(m.get_mpz_t(),randstate,n.get_mpz_t());

    cout<<"pt0 : "<<pt0<<endl;
    cout<<"pt1 : "<<pt1<<endl;	
    cout<<"m : "<<m<<endl;

    mpz_class ct0 = p.encrypt(pt0);
    mpz_class ct1 = p.encrypt(pt1);
    mpz_class sum = p.add(ct0, ct1);
    mpz_class prod = p.constMult(m,ct0);
    //    mpz_class diff = p.constMult(-1, ct0);
    mpz_class diff = p.sub(ct0, ct1);
    
    assert(pp.decrypt(ct0) == pt0);
    assert(pp.decrypt(ct1) == pt1);
    assert(pp.decrypt(sum) == (pt0+pt1)%n);
    mpz_class d = pt0 - pt1;
    if (d < 0) {
        d += n;
    }
    assert( pp.decrypt(diff) == d);
    assert(pp.decrypt(prod) == (m*pt0)%n);
    
    cout << " passed" << endl;
}


static void
test_paillier_fast()
{
    cout << "Test Paillier Fast..." << flush;
    
    gmp_randstate_t randstate;
    gmp_randinit_default(randstate);
    gmp_randseed_ui(randstate,time(NULL));
    
    auto sk = Paillier_priv_fast::keygen(randstate,600);
    Paillier_priv_fast pp(sk,randstate);
    
    auto pk = pp.pubkey();
    mpz_class n = pk[0];
    Paillier p(pk,randstate);
    
    mpz_class pt0, pt1,m;
    mpz_urandomm(pt0.get_mpz_t(),randstate,n.get_mpz_t());
    mpz_urandomm(pt1.get_mpz_t(),randstate,n.get_mpz_t());
    mpz_urandomm(m.get_mpz_t(),randstate,n.get_mpz_t());
    
    mpz_class ct0 = pp.encrypt(pt0);
    mpz_class ct1 = pp.encrypt(pt1);
    mpz_class sum = p.add(ct0, ct1);
    mpz_class prod = p.constMult(m,ct0);
    //    mpz_class diff = p.constMult(-1, ct0);
    mpz_class diff = p.sub(ct0, ct1);
    
    assert(pp.decrypt(ct0) == pt0);
    assert(pp.decrypt(ct1) == pt1);
    assert(pp.decrypt(sum) == (pt0+pt1)%n);
    mpz_class d = pt0 - pt1;
    if (d < 0) {
        d += n;
    }
    assert( pp.decrypt(diff) == d);
    assert(pp.decrypt(prod) == (m*pt0)%n);
    
    cout << " passed" << endl;
}

static void paillier_perf(unsigned int k, unsigned int a_bits, size_t n_iteration)
{
    cout << "Test Paillier performances ..." << endl;
    
    cout << "k = " << k << "\n a_bits = " << a_bits << "\n" << n_iteration << " iterations" << endl;
    
    gmp_randstate_t randstate;
    gmp_randinit_default(randstate);
    gmp_randseed_ui(randstate,time(NULL));
    
    auto sk = Paillier_priv::keygen(randstate,k,a_bits);
    Paillier_priv pp(sk,randstate);
    
    auto pk = pp.pubkey();
    mpz_class n = pk[0];
    Paillier p(pk,randstate);
    
    mpz_class pt0, pt1,m;
    mpz_urandomm(pt0.get_mpz_t(),randstate,n.get_mpz_t());
    mpz_urandomm(pt1.get_mpz_t(),randstate,n.get_mpz_t());
    mpz_urandomm(m.get_mpz_t(),randstate,n.get_mpz_t());
    
    mpz_class ct0 = p.encrypt(pt0);
    mpz_class ct1 = p.encrypt(pt1);
    mpz_class sum = p.add(ct0, ct1);
    mpz_class prod = p.constMult(m,ct0);
    //    mpz_class diff = p.constMult(-1, ct0);
    mpz_class diff = p.sub(ct0, ct1);
    
    assert(pp.decrypt(ct0) == pt0);
    assert(pp.decrypt(ct1) == pt1);
    assert(pp.decrypt(sum) == (pt0+pt1)%n);
    mpz_class d = pt0 - pt1;
    if (d < 0) {
        d += n;
    }
    assert( pp.decrypt(diff) == d);
    assert(pp.decrypt(prod) == (m*pt0)%n);
    
    struct timespec t0,t1;

    vector<mpz_class> ct(n_iteration);
    clock_gettime(CLOCK_THREAD_CPUTIME_ID,&t0);
    for (size_t i = 0; i < n_iteration; i++) {
        mpz_class pt;
        mpz_urandomm(pt.get_mpz_t(),randstate,n.get_mpz_t());
        ct[i] = p.encrypt(pt);
    }
    clock_gettime(CLOCK_THREAD_CPUTIME_ID,&t1);
    uint64_t t = (((uint64_t)t1.tv_sec) - ((uint64_t)t0.tv_sec) )* 1000000000 + (t1.tv_nsec - t0.tv_nsec);
    cerr << "public encryption: "<<  ((double)t/1000000)/n_iteration <<"ms per plaintext" << endl;

    clock_gettime(CLOCK_THREAD_CPUTIME_ID,&t0);
    for (size_t i = 0; i < n_iteration; i++) {
        mpz_class pt;
        mpz_urandomm(pt.get_mpz_t(),randstate,n.get_mpz_t());
        pp.encrypt(pt);
    }
    clock_gettime(CLOCK_THREAD_CPUTIME_ID,&t1);
    t = (((uint64_t)t1.tv_sec) - ((uint64_t)t0.tv_sec) )* 1000000000 + (t1.tv_nsec - t0.tv_nsec);
    cerr << "private encryption: "<<  ((double)t/1000000)/n_iteration <<"ms per plaintext" << endl;

    clock_gettime(CLOCK_THREAD_CPUTIME_ID,&t0);
    for (size_t i = 0; i < n_iteration; i++) {
        mpz_class pt;
        mpz_urandomm(pt.get_mpz_t(),randstate,n.get_mpz_t());
        pp.fast_encrypt_precompute(pt);
    }
    clock_gettime(CLOCK_THREAD_CPUTIME_ID,&t1);
    t = (((uint64_t)t1.tv_sec) - ((uint64_t)t0.tv_sec) )* 1000000000 + (t1.tv_nsec - t0.tv_nsec);
    cerr << "private encryption with precomputation: "<<  ((double)t/1000000)/n_iteration <<"ms per plaintext" << endl;

    clock_gettime(CLOCK_THREAD_CPUTIME_ID,&t0);
    for (size_t i = 0; i < n_iteration; i++) {
        pp.decrypt(ct[i]);
    }
    clock_gettime(CLOCK_THREAD_CPUTIME_ID,&t1);
    t = (((uint64_t)t1.tv_sec) - ((uint64_t)t0.tv_sec) )* 1000000000 + (t1.tv_nsec - t0.tv_nsec);
    cerr << "decryption: "<<  ((double)t/1000000)/n_iteration <<"ms per cyphertext" << endl;

}


static void paillier_fast_perf(unsigned int k, size_t n_iteration)
{
    cout << "Test Paillier Fast performances ..." << endl;
    
    cout << "k = " << k << "\n" << n_iteration << " iterations" << endl;
    
    gmp_randstate_t randstate;
    gmp_randinit_default(randstate);
    gmp_randseed_ui(randstate,time(NULL));
    
    auto sk = Paillier_priv_fast::keygen(randstate,k);
    Paillier_priv_fast pp(sk,randstate);
    
    auto pk = pp.pubkey();
    mpz_class n = pk[0];
//    Paillier p(pk,randstate);
    
    mpz_class pt0, pt1,m;
    mpz_urandomm(pt0.get_mpz_t(),randstate,n.get_mpz_t());
    mpz_urandomm(pt1.get_mpz_t(),randstate,n.get_mpz_t());
    mpz_urandomm(m.get_mpz_t(),randstate,n.get_mpz_t());
    
    struct timespec t0,t1;
    uint64_t t;
    
    vector<mpz_class> ct(n_iteration);

    clock_gettime(CLOCK_THREAD_CPUTIME_ID,&t0);
    for (size_t i = 0; i < n_iteration; i++) {
        mpz_class pt;
        mpz_urandomm(pt.get_mpz_t(),randstate,n.get_mpz_t());
        ct[i] = pp.encrypt(pt);
    }
    clock_gettime(CLOCK_THREAD_CPUTIME_ID,&t1);
    t = (((uint64_t)t1.tv_sec) - ((uint64_t)t0.tv_sec) )* 1000000000 + (t1.tv_nsec - t0.tv_nsec);
    cerr << "private encryption with generator precomputations: "<<  ((double)t/1000000)/n_iteration <<"ms per plaintext" << endl;
    
    clock_gettime(CLOCK_THREAD_CPUTIME_ID,&t0);
    for (size_t i = 0; i < n_iteration; i++) {
        pp.decrypt(ct[i]);
    }
    clock_gettime(CLOCK_THREAD_CPUTIME_ID,&t1);
    t = (((uint64_t)t1.tv_sec) - ((uint64_t)t0.tv_sec) )* 1000000000 + (t1.tv_nsec - t0.tv_nsec);
    cerr << "decryption: "<<  ((double)t/1000000)/n_iteration <<"ms per cyphertext" << endl;
    
}
static void
test_gm()
{
    cout << "Test GM ..." << flush;
    
    gmp_randstate_t randstate;
    gmp_randinit_default(randstate);
    gmp_randseed_ui(randstate,time(NULL));

    auto sk = GM_priv::keygen(randstate);
    GM_priv pp(sk,randstate);
    
    auto pk = pp.pubkey();
    GM p(pk,randstate);
    
    bool b0 = true; //(bool)RandomBits_long(1);
    bool b1 = false; //(bool)RandomBits_long(1);
    
    mpz_class ct0 = p.encrypt(b0);
    mpz_class ct1 = p.encrypt(b1);
    mpz_class XOR = p.XOR(ct0, ct1);
    mpz_class rerand = p.reRand(ct0);
    
    assert(pp.decrypt(pk[1]) == true);
    assert(pp.decrypt(ct0) == b0);
    assert(pp.decrypt(ct1) == b1);
    assert(pp.decrypt(XOR) == (b0 xor b1));
    assert(pp.decrypt(rerand) == b0);

    cout << " passed" << endl;
}

/**
* add by andy 2018-1-15
**/

//产生长度为n的随机排列
map<size_t,size_t> genRandomPermutation(const size_t &n, gmp_randstate_t state)
{
    map<size_t,size_t> perm;
    
    for (size_t i = 0; i < n; i++)
    {
        perm[i] = i;
		cout<<perm[i]<<"  ";
    }
    
	cout<<endl;
	
    for (size_t i = 0; i < n; i++)
    {
        unsigned long randomValue = gmp_urandomm_ui(state,n);
        swap(perm[i], perm[randomValue]);
        cout<<"after "<<i+1<<" perming........"<<endl;
	for(size_t i =0;i<n;i++)
	{
		cout<<perm[i]<<" ";
	}
	cout<<endl;
    }
	
    return perm;
}

//tao 需要打乱的数组
//perm 数组打乱后的次序
vector<mpz_class> RandomPermutaion(vector<mpz_class> tao,map<size_t,size_t> &perm,gmp_randstate_t randstate){
    
 /*    //原始数据
    size_t k =5;	
	vector<mpz_class> tao,data_;
	cout<<"origin tao : "<<endl;
	for(size_t i= 0;i<k;i++)
	{
	   tao.push_back(2*i+1);
           data_.push_back(i);
	   cout<<tao[i]<<" ";
	}
	cout<<endl; */

    cout<<"testing genRandomPermutation ..........."<<endl;
	/* map<size_t,size_t>perm;
	for(size_t i=0;i<k;i++)
	{
	     perm[i] = i ;
	} */
	size_t k = tao.size();//k表示数组长度
	perm = genRandomPermutation(k,randstate);
	cout<<"final perm .........."<<endl;
	for(size_t i =0;i<k;i++)
	{
	    cout<<perm[i]<<" ";
	}
	cout<<endl;
	
	
	//client
	cout<<"对数组tao进行随机排列 "<<endl;
	vector<mpz_class> tao_perm(k);
	for(size_t i =0;i<k;i++)
	{
	    tao_perm[i]= tao[perm[i]];
		cout<<tao_perm[i]<<" ";
	}
	cout<<endl;
	return tao_perm;
}


vector<mpz_class> unpermpermuteResult(vector<mpz_class> e_u,map<size_t,size_t>  perm)
{
	size_t k = e_u.size();
	cout<<"unpermpermuteResult  K : "<<k<<endl;
	vector<mpz_class> u(k);
        map<size_t,size_t>  perm_ =perm;
	for(size_t i =0;i<k;i++)
	{
	    u[perm_[i]] = e_u[i];
	}
	cout<<"u ......"<<endl;
	for(size_t i=0;i<k;i++)
	{
	    cout<<u[i]<<" ";
	}
	cout<<endl;
	return u;
}





mpz_class Encrypted_LSB(mpz_class T,mpz_class i,mpz_class n,gmp_randstate_t randstate,Paillier p,Paillier_priv pp)
{
    //T = p.encrypt(T);
	
	//选择随机数r
	mpz_class r,res;
	mpz_urandomm(r.get_mpz_t(),randstate,n.get_mpz_t());
        cout<<"r : "<<r<<endl;
	mpz_class Y = p.add(p.encrypt(r),T);
	
	//alice do
	mpz_class a,b=2;
        cout<<"b : "<<b.get_mpz_t()<<endl;
	mpz_class y = pp.decrypt(Y);
        cout<<"y : "<<pp.decrypt(Y)<<endl;
        mpz_cdiv_r (res.get_mpz_t(), y.get_mpz_t(),b.get_mpz_t()); 
        cout<<"res : "<<res<<endl;
	if(res==0)
	{
	    a=p.encrypt(0);
	}else
	{
	    a=p.encrypt(1);
	}
	//alice end
	
	//bob do 
	mpz_class e_xi;
        mpz_cdiv_r (res.get_mpz_t(), r.get_mpz_t(), b.get_mpz_t());
	if(res==0)
	{
	    e_xi = a;
	}else
	{
	    e_xi = p.sub(p.encrypt(1),a);
	}
        cout<<"x"<<i<<" : "<<pp.decrypt(e_xi)<<endl;
    return e_xi;
	
}

/*
*求乘法逆元
*/
void exgcd(mpz_class a, mpz_class b, mpz_class& d, mpz_class& x, mpz_class& y){
	if (!b){
		d = a;
		x = 1;
		y = 0;
	}
	else
	{
		exgcd(b, a%b, d, y, x);
		y -= x*(a / b);
	}
}

mpz_class inv(mpz_class a, mpz_class p){
	mpz_class d, x, y;
	exgcd(a, p, d, x, y);
        if(d==1)
        {
           return (x + p) % p ;
        }
        return -1;
}


//二进制转为10进制
mpz_class bits2mpz(vector<mpz_class> vec,int m,Paillier p,Paillier_priv pp)
{
	mpz_class U,t_i;
        mpz_t a;
	mpz_init_set_ui(a, 2);  
	U = p.encrypt(0);
	 for(int i=0;i<m;i++)
	 {
	    mpz_pow_ui(t_i.get_mpz_t(), a, i);//计算a的i次方
            cout<<"t_i : "<<t_i<<endl;
	        mpz_class temp = p.constMult(t_i,vec[i]);
            cout<<"temp : "<<pp.decrypt(temp)<<endl;
            U = p.add(temp,U);
            cout<<"U : "<<pp.decrypt(U)<<endl;
	 }
	return U;
}


//验证SBD位分解是否正确
mpz_class SVR(mpz_class E_x,vector<mpz_class>vec_Ex,int m,mpz_class n,Paillier p,Paillier_priv pp,gmp_randstate_t randstate)
{
     vector<mpz_class> vec_exi = vec_Ex;
     mpz_class r,U; 
         U = bits2mpz(vec_Ex,m,p,pp);//二进制转为10进制
         

	 mpz_class V = p.sub(U,E_x);
	 mpz_urandomm(r.get_mpz_t(),randstate,n.get_mpz_t());//随机选择r
	 mpz_class W = p.constMult(r,V);
	 

	 //alice
	 mpz_class d_w = pp.decrypt(W);
         cout<<"d_w : "<<d_w<<endl;
	 mpz_class ta;
	 if(d_w==0)
	 {
	    ta =1;
	 }else
	 {
	    ta =0;
	 }
	 return ta;

}

//位分解
vector<mpz_class> SBD(mpz_class E_x,mpz_class n,int m,gmp_randstate_t randstate,Paillier p,Paillier_priv pp)
{
     vector<mpz_class> vec_Exi;
     mpz_class l = inv(2,n);
     cout<<"l : "<<l<<endl;
     cout<<"m : "<<m<<endl;
     step2: 
     mpz_class E_xi,Z,T = E_x;
     for(int i=0;i<m;i++)
     {
	E_xi = Encrypted_LSB(T,i,n,randstate,p,pp);
	Z = p.sub(T,E_xi);
	T = p.constMult(l,Z);
        vec_Exi.push_back(E_xi);
     }
     mpz_class ta = SVR(E_x,vec_Exi,m,n,p,pp,randstate);
     cout<<"ta : "<<ta<<endl;
     if(ta == 1){
         return vec_Exi;
     }else
     {
         cout<<"SBD failed ! "<<endl;
         //goto step2;
     }
     return vec_Exi ;
}
//安全的乘法
mpz_class SM(mpz_class e_a,mpz_class e_b,mpz_class n,Paillier p,Paillier_priv pp,gmp_randstate_t randstate)
{
    mpz_class r_a,r_b;
	mpz_urandomm(r_a.get_mpz_t(),randstate,n.get_mpz_t());//随机选择r_a
	mpz_urandomm(r_b.get_mpz_t(),randstate,n.get_mpz_t());//随机选择r_b
	mpz_class a_ = p.add(e_a,p.encrypt(r_a));
	mpz_class b_ = p.add(e_b,p.encrypt(r_b));
	
	//send a_ ,b_ to alice 
	
	//alice
	mpz_class y_a = pp.decrypt(a_);
	mpz_class y_b = pp.decrypt(b_);
	
	//计算y_a*y_b
	mpz_class h = y_a*y_b%n;
	mpz_class e_h = p.encrypt(h);//e_h=(e_a+r_a)*(e_b+r_b)
	
	// send e_h to bob
	
	//bob do 
	mpz_class temp = p.constMult(r_b,e_a);
	mpz_class s = p.sub(e_h,temp);//e_h -r_b*e_a
	temp = p.constMult(r_a,e_b);
	s = p.sub(s,temp);
	mpz_class result = p.sub(s,p.encrypt(r_a*r_b));
	cout<<"result : "<<pp.decrypt(result)<<endl;
	return result;	
}

//两个比特位o1,o2取大
mpz_class SBOR(mpz_class o1,mpz_class o2,mpz_class n,Paillier p,Paillier_priv pp,gmp_randstate_t randstate)
{
     mpz_class min_o1o2 = SM(o1,o2,n,p,pp,randstate);
	 mpz_class add_o1o2 = p.add(o1,o2);
	 mpz_class max_o1o2 = p.sub(add_o1o2,min_o1o2);
	  
	 cout<<"max_o1o2 : "<<pp.decrypt(max_o1o2)<<endl;
	return max_o1o2;
}



static void test_bToe(Paillier p,Paillier_priv pp,gmp_randstate_t randstate,mpz_class N)
{
	//初始化pt_n ,n个明文,ct_n，n个密文
	vector<mpz_class> pt_n,ct_n;
	mpz_class ptk,ctk,temp;
	int n = 10;
	int k = 3;
    for(int i = 0;i<n;i++){
		pt_n.push_back(i);
		cout<<"ptn"<<i<<" : "<<i<<endl;
		temp = p.encrypt(pt_n[i]);
		ct_n.push_back(temp);
	}
	ptk = pt_n[k];  //下标为3的值为最小值
	ctk = p.encrypt(ptk); //E(I_min)
	
	cout<<"C1:从0到n下标依次与I_min作差（密文）"<<endl;
	vector<mpz_class> tao,tao_perm;
	mpz_class ri;
	for(int i=0;i<n;i++){
		temp = p.sub(pt_n[i],ptk);//E(i-I_min)
		mpz_urandomm(ri.get_mpz_t(),randstate,N.get_mpz_t());
		temp = p.constMult(ri,temp);//E(ri*(i-I_min))
		tao.push_back(temp);
	}
	
	cout<<"c1 对密文进行随机排列"<<endl;
        map<size_t,size_t> perm;
        tao_perm = RandomPermutaion(tao,perm,randstate);
	
	cout<<"send tao_perm to c2 "<<endl;
	
	//c2 do
	vector<mpz_class> plain,u;
	for(int i=0;i<n;i++){
		plain.push_back(pp.decrypt(tao_perm[i]));
	    cout<<"plian"<<i<<" : "<<plain[i]<<endl;
		if(plain[i]==0){
			u.push_back(p.encrypt(1));
		}else{
			u.push_back(p.encrypt(0));
		}
	}
     
    //c2 send u to c1

    for(int i=0;i<n;i++)
	{
		cout<<"u"<<i<<" : "<<pp.decrypt(u[i])<<" ";
	}
	cout<<endl;
	
	
    //c1 do 
    vector<mpz_class> V;
    V = unpermpermuteResult(u,perm);//order normal
	
	int m,s = 8;
	frexp(s,&m);
	mpz_class E_d = p.encrypt(s);
        vector<mpz_class> vec_Edi;
	vec_Edi = SBD(E_d,N,m,randstate,p,pp);//对距离E_d进行位分解，E_d =<E_d1,E_d2,...,E_dm-1>
	vector<mpz_class> E_dmaxi(m);
        vector<mpz_class> E_dis(n);
	//将距离E_d设为最大值
	for(int i=0;i<n;i++)
        {
		for(int j=0;j<m;j++)
		{
			E_dmaxi[j] = SBOR(V[i],vec_Edi[j],N,p,pp,randstate);
		}
           E_dis[i]=bits2mpz(E_dmaxi,m,p,pp);
	}

	for(int i =0 ;i<n;i++)
        {
            cout<<"decrypt"<<i<<" : "<<pp.decrypt(E_dis[i])<<endl;
        }
}
/*
* add end 
**/
int main(int ac, char **av)
{
    SetSeed(to_ZZ(time(NULL)));
    
/**
* add by andy 2018-1-15
*/

//test_paillier_sub();

//test_getRandomPermutaion();

    gmp_randstate_t randstate;
    gmp_randinit_default(randstate);//设置随机数生成算法为默认
    gmp_randseed_ui(randstate,time(NULL));//设置随机化种子为当前时间，这几条语句的作用相当于标准C中的srand(time(NULL)); 
	//生成私钥
    auto sk = Paillier_priv::keygen(randstate,1024);
    Paillier_priv pp(sk,randstate);
    
	//生成公钥
    auto pk = pp.pubkey();
    mpz_class n = pk[0];
    Paillier p(pk,randstate);

  
/* 
 mpz_class a =3,b=4;
    mpz_class e_a = p.encrypt(a);
    mpz_class e_b = p.encrypt(b);
    mpz_class result = SM(e_a,e_b,n,p,pp,randstate);

    a=1,b=0;
    e_a = p.encrypt(a);
    e_b = p.encrypt(b);
    result = SBOR(e_a,e_b,n,p,pp,randstate); */

/* 
    int s =8;
    int m;
    frexp(s,&m);
    vector<mpz_class> vec_Exi;   

    mpz_class E_x = p.encrypt(s); 
    vec_Exi = SBD(E_x,n,m,randstate,p,pp); */
    

 /*   test_bToe(p,pp,randstate,n);

   int b = 9;
   mpz_class a =b;
   cout<<"a : "<<a<<endl;
   */
        map<size_t,size_t> permm;
        int k = 100;
        permm= genRandomPermutation(k,randstate);
	cout<<"final perm .........."<<endl;
	for(size_t i =0;i<k;i++)
	{
	    cout<<permm[i]<<" ";
	}
	cout<<endl;  


/**
* add end
*/






    
//    test_elgamal();
	//test_paillier();
	/* test_paillier_fast();
	test_gm();

    
    unsigned int k = 1024;
    unsigned int a_bits = 256;
    size_t n_iteration = 500;
    cout << endl;
    
//    paillier_perf(k,a_bits,n_iteration);
//    cout << endl;
    
    a_bits = 0;
    paillier_perf(k,a_bits,n_iteration);

    cout << endl;

    paillier_fast_perf(k, n_iteration); */
    
    return 0;
}
