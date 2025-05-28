package main

import (
	"fmt"
	"time"

	"github.com/tuneinsight/lattigo/v4/bfv"
	"github.com/tuneinsight/lattigo/v4/rlwe"
	"gonum.org/v1/gonum/stat"
)

// Функция измерения времени выполнения, возвращающая время в секундах
func measureTime(f func()) float64 {
	start := time.Now()
	f()
	return time.Since(start).Seconds()
}

type PerfTestResult struct {
	SetupTime   float64
	KeyGenTime  float64
	EncodeTime  float64
	EncryptTime float64
	AddTime     float64
	MultTime    float64
	DecryptTime float64
}

func perf_test() PerfTestResult {
	res := PerfTestResult{}

	// Установка параметров с корректной обработкой ошибок
	var params bfv.Parameters
	var err error
	res.SetupTime = measureTime(func() {
		params, err = bfv.NewParametersFromLiteral(bfv.ParametersLiteral{
			LogN: 13, // N = 8192
			LogQ: []int{55, 55},
			LogP: []int{55},
			T:    65537,
		})
		if err != nil {
			panic(fmt.Sprintf("error setting parameters: %v", err))
		}
	})

	// Генерация ключей
	var kgen rlwe.KeyGenerator
	var sk *rlwe.SecretKey
	var pk *rlwe.PublicKey
	var rlk *rlwe.RelinearizationKey

	res.KeyGenTime = measureTime(func() {
		kgen = rlwe.NewKeyGenerator(params.Parameters)
		sk = kgen.GenSecretKey()
		pk = kgen.GenPublicKey(sk)
		rlk = kgen.GenRelinearizationKey(sk, 1)
	})

	// Создание объектов для операций
	encryptor := rlwe.NewEncryptor(params.Parameters, pk)
	decryptor := rlwe.NewDecryptor(params.Parameters, sk)
	evaluator := bfv.NewEvaluator(params, rlwe.EvaluationKey{Rlk: rlk})
	encoder := bfv.NewEncoder(params)

	// Подготовка данных
	plaintext1 := make([]uint64, params.N())
	plaintext2 := make([]uint64, params.N())
	for i := range plaintext1 {
		plaintext1[i] = 1
		plaintext2[i] = 2
	}

	// Кодирование
	polyPlain1 := bfv.NewPlaintext(params, 0)
	polyPlain2 := bfv.NewPlaintext(params, 0)

	res.EncodeTime = measureTime(func() {
		encoder.Encode(plaintext1, polyPlain1)
		encoder.Encode(plaintext2, polyPlain2)
	})

	// Шифрование
	cipher1 := rlwe.NewCiphertext(params.Parameters, 1, 0)
	cipher2 := rlwe.NewCiphertext(params.Parameters, 1, 0)

	res.EncryptTime = measureTime(func() {
		encryptor.Encrypt(polyPlain1, cipher1)
		encryptor.Encrypt(polyPlain2, cipher2)
	})

	// Гомоморфное сложение
	cipherAdd := rlwe.NewCiphertext(params.Parameters, 1, 0)

	res.AddTime = measureTime(func() {
		evaluator.Add(cipher1, cipher2, cipherAdd)
	})

	// Гомоморфное умножение
	cipherMult := rlwe.NewCiphertext(params.Parameters, 2, 0)

	res.MultTime = measureTime(func() {
		evaluator.Mul(cipher1, cipher2, cipherMult)
		cipherRelinMult := rlwe.NewCiphertext(params.Parameters, 1, 0)
		evaluator.Relinearize(cipherMult, cipherRelinMult)
	})

	// Расшифрование
	decryptedPlain := bfv.NewPlaintext(params, 0)

	res.DecryptTime = measureTime(func() {
		decryptor.Decrypt(cipherAdd, decryptedPlain)
	})

	// Декодирование и проверка результата
	result := make([]uint64, params.N())
	encoder.Decode(decryptedPlain, result)

	return res
}

func main() {
	fmt.Println("Lattigo BFV Performance Test\n------------------")

	n := 100
	fmt.Printf("Performing %v iterations...\n", n)

	var setupTime []float64
	var keyGenTime []float64
	var encodeTime []float64
	var encryptTime []float64
	var addTime []float64
	var multTime []float64
	var decryptTime []float64

	for i := 0; i < n; i++ {
		times := perf_test()
		setupTime = append(setupTime, times.SetupTime)
		keyGenTime = append(keyGenTime, times.KeyGenTime)
		encodeTime = append(encodeTime, times.EncodeTime)
		encryptTime = append(encryptTime, times.EncryptTime)
		addTime = append(addTime, times.AddTime)
		multTime = append(multTime, times.MultTime)
		decryptTime = append(decryptTime, times.DecryptTime)
	}

	fmt.Printf("Average parameter setup time: %.6f±%f s\n", stat.Mean(setupTime, nil), stat.StdDev(setupTime, nil))
	fmt.Printf("Average key generation time: %.6f±%f s\n", stat.Mean(keyGenTime, nil), stat.StdDev(keyGenTime, nil))
	fmt.Printf("Average encoding time: %.6f±%f s\n", stat.Mean(encodeTime, nil), stat.StdDev(encodeTime, nil))
	fmt.Printf("Average encryption time: %.6f±%f s\n", stat.Mean(encryptTime, nil), stat.StdDev(encryptTime, nil))
	fmt.Printf("Average addition time: %.6f±%f s\n", stat.Mean(addTime, nil), stat.StdDev(addTime, nil))
	fmt.Printf("Average multiplication time: %.6f±%f s\n", stat.Mean(multTime, nil), stat.StdDev(multTime, nil))
	fmt.Printf("Average decryption time: %.6f±%f s\n", stat.Mean(decryptTime, nil), stat.StdDev(decryptTime, nil))
}
