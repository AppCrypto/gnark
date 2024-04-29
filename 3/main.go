package main

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/native/sw_bls24315"

	bls24315 "github.com/consensys/gnark-crypto/ecc/bls24-315"
)

// 判断C=G*R，G是基点
type g1varScalarMulBase struct {
	//公开点
	C sw_bls24315.G1Affine `gnark:",public"`
	R frontend.Variable
}

func (circuit *g1varScalarMulBase) Define(api frontend.API) error {
	expected := sw_bls24315.G1Affine{}
	//标量乘基点
	expected.ScalarMulBase(api, circuit.R)
	//判断两点是否相等
	expected.AssertIsEqual(api, circuit.C)
	return nil
}

func main() {
	//创建电路和见证人
	var circuit, witness g1varScalarMulBase
	var c bls24315.G1Affine
	//基点
	gJac, _, _, _ := bls24315.Generators()
	//创建标量
	var r big.Int
	r.SetInt64(123)
	//为标量赋值
	witness.R = r
	//标量乘基点
	gJac.ScalarMultiplication(&gJac, &r)
	c.FromJacobian(&gJac)
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
