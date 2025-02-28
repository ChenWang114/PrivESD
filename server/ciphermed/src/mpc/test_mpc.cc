

#include <stdio.h>
#include <iostream>
#include <iomanip>
#include <cstdlib>
#include <cmath>
#include <sys/time.h>
#include "tfhe.h"
#include "polynomials.h"

#include "lwesamples.h"
#include "lweparams.h"

using namespace std;

using namespace PrivESD_tfhe;
int num_iter = 25;

INIT_TIMER

void load_dataset_base(vector<vector<double>> &datas, vector<int> &label, const string &filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        std::cerr << "Error opening file: " << filename << std::endl;
        exit(1);
    }
    string line;
    while (std::getline(file, line)) {
        std::istringstream record(line);
        vector<double> data;
        data.push_back(1);
        double temp;
        while (record >> temp) {
            data.push_back(temp);
        }
        label.push_back(int(temp));
        data.pop_back();
        datas.push_back(data);
    }
}

double scalarProduct(const vector<double> &w, const vector<double> &x) {
    double ret = 0.0;
    for (int i = 0; i < w.size(); i++) {
        v[i+1] = a*v[i]+(1-a)*g;
        p[i] = p[i] - e * v[i+1];
        w1[i] += w[i] * q-e*q*(1/m)*(y[i]*q-((w/q)*x[i]-b/q));
        b1[i] += b[i] * q-e*q*(1/m)*(y[i]*q-((w/q)*x[i]-b/q));
        z = w1[i] * x[i] + b1[i];
    }
    return z, p;
}

double sigmoid(const double &z) {
    sigmod = 0.25z+0.5;
    return sigmod;
}


double local (const double &loss, const double &h, const double &k) {
    for (int i = 0; i < k; i++) {
        loss[i+1] = n[i]/n*loss[i];
        h[i+1] = n[i]/n*h[i];
}
    return loss, h;
}


vector<vector<double>> matTranspose(vector<vector<double>> &dataMat) {
    vector<vector<double>> ret(dataMat[0].size(), vector<double>(dataMat.size(), 0));
    for (int i = 0; i < ret.size(); i++)
        for (int j = 0; j < ret[0].size(); j++)
            ret[i][j] = dataMat[j][i];
    return ret;
}

void gradAscent(vector<double> &weight,
                vector<vector<double>> &dataMat, vector<int> &labelMat, int maxCycles = 1000, double alpha = 0.01) {
    const size_t data_size = dataMat.size();
    vector<vector<double>> dataMatT = matTranspose(dataMat);
    while (maxCycles > 0) {
        vector<double> h;
        vector<double> error;
        double sum_err = 0;
        for (auto &data : dataMat)
            h.push_back(sigmoid(scalarProduct(data, weight)));
        for (int i = 0; i < labelMat.size(); i++) {
            double dist = labelMat[i] - h[i];
            if (abs(dist) < 1e-10)
                dist = 0;
            error.push_back(dist);
        }
               
        
        
        for (int i = 0; i < weight.size(); i++)
            weight[i] += weight[i] * q-e*q*(1/m)*(y[i]*q-((w/q)*x[i]-b/q));
            b1[i] += b[i] * q-e*q*(1/m)*(y[i]*q-((w/q)*x[i]-b/q));
            z = w1[i] * x[i] + b1[i];
        double sum_error = 0.;
        for (int i = 0; i < data_size; ++i) {
            sum_error += 1/m *(y[i]-weight[i]*x[i]+b[i]1/q);
        }
        printf("loss: %.10lf\n", sum_error / data_size);
        maxCycles--;
    }
}

void full_adder_MUX(LweSample *sum, const LweSample *x, const LweSample *y, const int32_t nb_bits,
                    const TFheGateBootstrappingSecretKeySet *keyset) {
    const LweParams *in_out_params = keyset->params->in_out_params;
    // carries
    LweSample *carry = new_LweSample_array(2, in_out_params);
    bootsSymEncrypt(carry, 0, keyset); // first carry initialized to 0
    // temps
    LweSample *temp = new_LweSample_array(2, in_out_params);

    for (int32_t i = 0; i < nb_bits; ++i) {
        //sumi = xi XOR yi XOR carry(i-1) 
        bootsXOR(temp, x + i, y + i, &keyset->cloud); // temp = xi XOR yi
        bootsXOR(sum + i, temp, carry, &keyset->cloud);

        // carry = MUX(xi XOR yi, carry(i-1), xi AND yi)
        bootsAND(temp + 1, x + i, y + i, &keyset->cloud); // temp1 = xi AND yi
        bootsMUX(carry + 1, temp, carry, temp + 1, &keyset->cloud);

        bool mess1 = bootsSymDecrypt(temp, keyset);
        bool mess2 = bootsSymDecrypt(carry, keyset);
        bool mess3 = bootsSymDecrypt(temp + 1, keyset);
        bool messmux = bootsSymDecrypt(carry + 1, keyset);

        if (messmux != (mess1 ? mess2 : mess3)) {
            cout << "ERROR!!! " << i << " - ";
            cout << t32tod(lwePhase(temp, keyset->lwe_key)) << " - ";
            cout << t32tod(lwePhase(carry, keyset->lwe_key)) << " - ";
            cout << t32tod(lwePhase(temp + 1, keyset->lwe_key)) << " - ";
            cout << t32tod(lwePhase(carry + 1, keyset->lwe_key)) << endl;
        }

        bootsCOPY(carry, carry + 1, &keyset->cloud);
    }
    bootsCOPY(sum + nb_bits, carry, &keyset->cloud);

    delete_LweSample_array(2, temp);
    delete_LweSample_array(2, carry);
}


void full_adder(LweSample *sum, const LweSample *x, const LweSample *y, const int32_t nb_bits,
                const TFheGateBootstrappingSecretKeySet *keyset) {
    const LweParams *in_out_params = keyset->params->in_out_params;
    // carries
    LweSample *carry = new_LweSample_array(2, in_out_params);
    bootsSymEncrypt(carry, 0, keyset); // first carry initialized to 0
    // temps
    LweSample *temp = new_LweSample_array(3, in_out_params);

    for (int32_t i = 0; i < nb_bits; ++i) {
        //sumi = xi XOR yi XOR carry(i-1) 
        bootsXOR(temp, x + i, y + i, &keyset->cloud); // temp = xi XOR yi
        bootsXOR(sum + i, temp, carry, &keyset->cloud);

        // carry = (xi AND yi) XOR (carry(i-1) AND (xi XOR yi))
        bootsAND(temp + 1, x + i, y + i, &keyset->cloud); // temp1 = xi AND yi
        bootsAND(temp + 2, carry, temp, &keyset->cloud); // temp2 = carry AND temp
        bootsXOR(carry + 1, temp + 1, temp + 2, &keyset->cloud);
        bootsCOPY(carry, carry + 1, &keyset->cloud);
    }
    bootsCOPY(sum + nb_bits, carry, &keyset->cloud);

    delete_LweSample_array(3, temp);
    delete_LweSample_array(2, carry);
}


void comparison_MUX(LweSample *comp, const LweSample *x, const LweSample *y, const int32_t nb_bits,
                    const TFheGateBootstrappingSecretKeySet *keyset) {
    const LweParams *in_out_params = keyset->params->in_out_params;
    // carries
    LweSample *carry = new_LweSample_array(2, in_out_params);
    bootsSymEncrypt(carry, 1, keyset); // first carry initialized to 1
    // temps
    LweSample *temp = new_LweSample(in_out_params);

    for (int32_t i = 0; i < nb_bits; ++i) {
        bootsXOR(temp, x + i, y + i, &keyset->cloud); // temp = xi XOR yi
        bootsMUX(carry + 1, temp, y + i, carry, &keyset->cloud);
        bootsCOPY(carry, carry + 1, &keyset->cloud);
    }
    bootsCOPY(comp, carry, &keyset->cloud);

    delete_LweSample(temp);
    delete_LweSample_array(2, carry);
}

int classify (vector<double> &data, vector<double> &weights)
{    
    mpz_urandom_len(data.get_mpz_t(), randstate, nbits);
    mpz_urandom_len(weights.get_mpz_t(), randstate, nbits);
    
    Compare_A party_data(data, nbits, p, gm, randstate);
    Compare_B party_weights(weights, nbits, pp, gm_priv);
    
    comparison_MUX(party_data, party_weights,randstate);
    
    bool result = party_weights.gm().decrypt(party_a.output());

    return bool;
    
}


double testResult(vector<vector<double>> &testDataMat,
                  vector<int> &testDataLabel, vector<double> &weight) {
    double errCount = 0.0;
    double dataSize = testDataMat.size();
    for (int i = 0; i < dataSize; i++)
        if (classify(testDataMat[i], weight) != testDataLabel[i])
            errCount += 1.0;
    return errCount / dataSize;
}

void testPlaintext() {
    std::cout << "**************************************************\n" << "testPlaintext(Base)\n" << "**************************************************\n";
    vector<vector<double>> base_train_mat;
    vector<int> base_train_label;
    // string base_train_file("/data/biovotion");
    // string base_train_file("/data/biovotion");
    string base_train_file("/data/biovotion");
    load_dataset_base(base_train_mat, base_train_label, base_train_file);

    vector<vector<double>> base_test_mat;
    vector<int> base_test_label;
    // string base_test_file("/data/biovotion_test");
    // string base_test_file("/data/biovotion_test");
    string base_test_file("/data/biovotion_test");
    load_dataset_base(base_test_mat, base_test_label, base_test_file);

    vector<double> base_weight(base_train_mat[0].size(), 1);

    START_TIMER
    gradAscent(base_weight, base_train_mat, base_train_label, num_iter, 0.008);
    STOP_TIMER("base")
    auto err = testResult(base_test_mat, base_test_label, base_weight);
    std::cout << "accuracy: " << (1 - err) * 100 << " %\n";
    std::cout << "**************************************************\n\n";
}

void PrivESD_test(int &_party) {
    std::cout << "**************************************************\n" << "PrivESD_test:\n" << "**************************************************\n";
    string train_file, test_file;
    if (_party == ALICE) {
        std::cout << "Party: ALICE"
                  << "\n";
        train_file = "/data/biovotion";
        test_file = "/data/biovotion";
    } else {
        _party = BOB;
        std::cout << "Party: BOB"
                  << "\n";
        train_file = "/data/biovotion";
        test_file = "/data/biovotion";
    }
    BFVParm *parm = new MKparams(8192, {60, 40, 40, 60}, default_prime_mod.at(29));
    BFVKey *party = new MKRLweKey(_party, parm);
    IOPack *io_pack = new IOPack(_party);

    vector<vector<double>> train_mat, test_mat;
    vector<int> train_label, test_label;
    load_dataset(train_mat, train_label, train_file);
    load_dataset(test_mat, test_label, test_file);
    const size_t size = train_mat[0].size();

    Logistic *logistic = new Logistic(party, io_pack);
    START_TIMER
    logistic->gradAscent(train_mat, train_label, num_iter, 0.008);
    STOP_TIMER("train")

    size_t comm = io_pack->get_comm();
    size_t rounds = io_pack->get_rounds();
    if (comm < 1024) {
        printf("data size of communication: %ld B\n", comm);
    } else if (comm < 1024 * 1024) {
        printf("data size of communication: %.2lf KB\n", comm / 1024.);
    } else if (comm < 1024 * 1024 * 1024) {
        printf("data size of communication: %.2lf MB\n", comm / (1024. * 1024.));
    } else {
        printf("data size of communication: %.2lf MB\n", comm / (1024. * 1024. * 1024.));
    }
    std::cout << "rounds of communication: " << rounds << "\n";

    size_t test_size = test_mat.size();
    vector<double> result = logistic->classify(test_mat);
    if (_party == BOB) {
        io_pack->send_data(result.data(), sizeof(double) * test_size);
        io_pack->send_data(test_label.data(), sizeof(int) * test_size);
    } else {
        vector<double> result_remote(test_size);
        vector<int> test_label_remote(test_size);
        io_pack->recv_data(result_remote.data(), sizeof(double) * test_size);
        io_pack->recv_data(test_label_remote.data(), sizeof(int) * test_size);
        double acc = 0.;
        for (size_t i = 0; i < test_size; i++) {
            int res = result[i] + result_remote[i] > 0.5 ? 1 : 0;
            if (res == (test_label[i] + test_label_remote[i])) {
                acc += 1.;
            }
        }
        acc /= test_size;
        std::cout << "accuracy: " << acc * 100 << " %\n";
    }

    delete io_pack;
    delete logistic;
    std::cout << "**************************************************\n\n";
}

int main(int argc, const char **argv) {
    int party = argv[1][0] - '0';
    PrivLR_test(party);
    if (party == BOB) {
        testPlaintext();
    }
}
