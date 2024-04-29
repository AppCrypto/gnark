package main

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bls24-315/fr"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/native/sw_bls24315"

	bls24315 "github.com/consensys/gnark-crypto/ecc/bls24-315"
)

// 验证C=A*B
type g1ScalarMul struct {
	//A未公开点
	A sw_bls24315.G1Affine
	//公开点
	C sw_bls24315.G1Affine `gnark:",public"`
	//标量未公开
	B frontend.Variable
}

func (circuit *g1ScalarMul) Define(api frontend.API) error {
	var expected sw_bls24315.G1Affine
	//点A乘标量
	expected.ScalarMul(api, circuit.A, circuit.B)
	//判断两点是否相等
	expected.AssertIsEqual(api, circuit.C)
	return nil
}

// 随机生成点
func randomPointG1() bls24315.G1Jac {

	p1, _, _, _ := bls24315.Generators()

	var r1 fr.Element
	var b big.Int
	_, _ = r1.SetRandom()
	p1.ScalarMultiplication(&p1, r1.BigInt(&b))

	return p1
}

func main() {
	//创建电路和见证人
	var circuit, witness g1ScalarMul
	//创建点a,c
	var a, c bls24315.G1Affine
	//随机生成点_a
	_a := randomPointG1()
	a.FromJacobian(&_a)
	//为见证人点A赋值——————————————Assign将椭圆曲线的点转到可以运算的G1Affine类型
	witness.A.Assign(&a)
	//创建标量
	var b big.Int
	b.SetInt64(123)
	//为标量赋值
	witness.B = b
	//点a乘标量
	_a.ScalarMultiplication(&_a, &b)
	c.FromJacobian(&_a)
	//为见证人点C赋值
	witness.C.Assign(&c)
	// because we are using 2-chains then the outer curve must correspond to the
	// inner curve. For inner BLS12-377 the outer curve is BW6-761.
	ccs, err := frontend.Compile(ecc.BW6_633.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		panic("compile failed: " + err.Error())
	}

	// create Groth16 setup. NB! UNSAFE
	pk, vk, err := groth16.Setup(ccs) // UNSAFE! Use MPC
	if err != nil {
		panic("setup failed: " + err.Error())
	}

	// create prover witness from the assignment
	secretWitness, err := frontend.NewWitness(&witness, ecc.BW6_633.ScalarField())
	if err != nil {
		panic("secret witness failed: " + err.Error())
	}

	// create public witness from the assignment
	publicWitness, err := secretWitness.Public()
	if err != nil {
		panic("public witness failed: " + err.Error())
	}

	circuitProof, err := groth16.Prove(ccs, pk, secretWitness)
	if err != nil {
		panic("proving failed: " + err.Error())
	}

	err = groth16.Verify(circuitProof, vk, publicWitness)
	if err != nil {
		panic("circuit verification failed: " + err.Error())
	}
}
