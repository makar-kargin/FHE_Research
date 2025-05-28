#include "seal/seal.h"
#include <chrono>
#include <iostream>
#include <vector>
#include <cmath>
#include <numeric>
#include <iomanip>

// Структура для хранения статистики
struct TimingStats {
    double mean;
    double stddev;
    
    // Вычисление среднего и стандартного отклонения
    static TimingStats calculate(const std::vector<double>& timings) {
        double sum = std::accumulate(timings.begin(), timings.end(), 0.0);
        double mean = sum / timings.size();
        
        double sq_sum = std::inner_product(timings.begin(), timings.end(), 
                                          timings.begin(), 0.0);
        double stddev = std::sqrt(sq_sum / timings.size() - mean * mean);
        
        return {mean, stddev};
    }
};

// Функция для форматированного вывода результатов
void printStats(const std::string& operation, const TimingStats& stats) {
    std::cout << "Average " << operation << ": " 
              << std::fixed << std::setprecision(6) << stats.mean 
              << "±" << std::setprecision(6) << stats.stddev << " s" << std::endl;
}

// Функция для замера времени одной операции
template<typename Func>
double measureSingleTime(Func f) {
    auto start = std::chrono::high_resolution_clock::now();
    f();
    auto end = std::chrono::high_resolution_clock::now();
    return std::chrono::duration<double>(end - start).count();
}

int main() {
    std::cout << "Microsoft SEAL BFV Performance Test\n------------------\n";
    
    // Количество итераций
    const int iterations = 100;
    std::cout << "Performing " << iterations << " iterations..." << std::endl;
    
    // Векторы для хранения результатов
    std::vector<double> contextTimes(iterations);
    std::vector<double> keyGenTimes(iterations);
    std::vector<double> encTimes(iterations);
    std::vector<double> addTimes(iterations);
    std::vector<double> multTimes(iterations);
    std::vector<double> decTimes(iterations);
    
    // Предварительная настройка параметров (один раз)
    seal::EncryptionParameters parms(seal::scheme_type::bfv);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(seal::CoeffModulus::BFVDefault(poly_modulus_degree));
    parms.set_plain_modulus(seal::PlainModulus::Batching(poly_modulus_degree, 20));
    
    // Запуск итераций
    for (int i = 0; i < iterations; i++) {
        // Создание контекста
        contextTimes[i] = measureSingleTime([&]() {
            seal::SEALContext context(parms);
        });
        
        seal::SEALContext context(parms);
        
        // Генерация ключей
        keyGenTimes[i] = measureSingleTime([&]() {
            seal::KeyGenerator keygen(context);
            auto secret_key = keygen.secret_key();
            seal::PublicKey public_key;
            keygen.create_public_key(public_key);
            seal::RelinKeys relin_keys;
            keygen.create_relin_keys(relin_keys);
        });
        
        // Создание ключей для тестирования
        seal::KeyGenerator keygen(context);
        auto secret_key = keygen.secret_key();
        seal::PublicKey public_key;
        keygen.create_public_key(public_key);
        seal::RelinKeys relin_keys;
        keygen.create_relin_keys(relin_keys);
        
        // Инициализация объектов для операций
        seal::Encryptor encryptor(context, public_key);
        seal::Evaluator evaluator(context);
        seal::Decryptor decryptor(context, secret_key);
        seal::BatchEncoder encoder(context);
        
        // Подготовка данных
        size_t slot_count = encoder.slot_count();
        std::vector<uint64_t> pod_vector1(slot_count, 1);
        std::vector<uint64_t> pod_vector2(slot_count, 2);
        
        seal::Plaintext plain1, plain2;
        encoder.encode(pod_vector1, plain1);
        encoder.encode(pod_vector2, plain2);
        
        // Шифрование
        seal::Ciphertext cipher1, cipher2;
        encTimes[i] = measureSingleTime([&]() {
            encryptor.encrypt(plain1, cipher1);
            encryptor.encrypt(plain2, cipher2);
        });
        
        // Гомоморфное сложение
        seal::Ciphertext cipher_add;
        addTimes[i] = measureSingleTime([&]() {
            evaluator.add(cipher1, cipher2, cipher_add);
        });
        
        // Гомоморфное умножение
        seal::Ciphertext cipher_mult;
        multTimes[i] = measureSingleTime([&]() {
            evaluator.multiply(cipher1, cipher2, cipher_mult);
            evaluator.relinearize_inplace(cipher_mult, relin_keys);
        });
        
        // Расшифрование
        seal::Plaintext decrypted_result;
        decTimes[i] = measureSingleTime([&]() {
            decryptor.decrypt(cipher_add, decrypted_result);
        });
    }
    
    // Вычисление и вывод статистики
    std::cout << std::endl;
    printStats("context creation time", TimingStats::calculate(contextTimes));
    printStats("key generation time", TimingStats::calculate(keyGenTimes));
    printStats("encryption time", TimingStats::calculate(encTimes));
    printStats("addition time", TimingStats::calculate(addTimes));
    printStats("multiplication time", TimingStats::calculate(multTimes));
    printStats("decryption time", TimingStats::calculate(decTimes));
    
    return 0;
}
