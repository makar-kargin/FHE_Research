#include <helib/helib.h>
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
    std::cout << "HElib BGV Performance Test\n------------------\n";
    
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
    
    // Параметры BGV схемы (фиксированы для всех итераций)
    unsigned long p = 65537;
    unsigned long m = 8192;
    unsigned long r = 1;
    unsigned long c = 2;
    
    // Запуск итераций
    for (int i = 0; i < iterations; i++) {
        // Инициализация контекста
        contextTimes[i] = measureSingleTime([&]() {
            helib::Context context = helib::ContextBuilder<helib::BGV>()
                .m(m).p(p).r(r).c(c).build();
        });
        
        // Создание контекста для текущей итерации
        helib::Context context = helib::ContextBuilder<helib::BGV>()
            .m(m).p(p).r(r).c(c).build();
        
        // Генерация ключей
        keyGenTimes[i] = measureSingleTime([&]() {
            helib::SecKey secretKey(context);
            secretKey.GenSecKey();
            helib::addSome1DMatrices(secretKey);
        });
        
        // Создание ключей для текущей итерации
        helib::SecKey secretKey(context);
        secretKey.GenSecKey();
        helib::addSome1DMatrices(secretKey);
        const helib::PubKey& publicKey = secretKey;
        
        // Получаем объект для шифрования
        const helib::EncryptedArray& ea = context.getEA();
        long nslots = ea.size();
        
        // Подготовка данных
        std::vector<long> plaintext1(nslots, 1);
        std::vector<long> plaintext2(nslots, 2);
        
        // Шифрование
        helib::Ctxt ctxt1(publicKey), ctxt2(publicKey);
        encTimes[i] = measureSingleTime([&]() {
            ea.encrypt(ctxt1, publicKey, plaintext1);
            ea.encrypt(ctxt2, publicKey, plaintext2);
        });
        
        // Гомоморфное сложение
        addTimes[i] = measureSingleTime([&]() {
            ctxt1 += ctxt2;
        });
        
        // Создаем новые шифртексты для умножения
        helib::Ctxt ctxt3(publicKey), ctxt4(publicKey);
        ea.encrypt(ctxt3, publicKey, plaintext1);
        ea.encrypt(ctxt4, publicKey, plaintext2);
        
        // Гомоморфное умножение
        multTimes[i] = measureSingleTime([&]() {
            ctxt3 *= ctxt4;
        });
        
        // Расшифрование
        std::vector<long> result(nslots);
        decTimes[i] = measureSingleTime([&]() {
            ea.decrypt(ctxt1, secretKey, result);
        });
    }
    
    // Вычисление и вывод статистики
    std::cout << std::endl;
    printStats("context initialization time", TimingStats::calculate(contextTimes));
    printStats("key generation time", TimingStats::calculate(keyGenTimes));
    printStats("encryption time", TimingStats::calculate(encTimes));
    printStats("addition time", TimingStats::calculate(addTimes));
    printStats("multiplication time", TimingStats::calculate(multTimes));
    printStats("decryption time", TimingStats::calculate(decTimes));
    
    return 0;
}
