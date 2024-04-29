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

// 两个点想加等于的第三点
type g1AddAssignAffine struct {
	A, B sw_bls24315.G1Affine
	C    sw_bls24315.G1Affine `gnark:",public"`
}

func (circuit *g1AddAssignAffine) Define(api frontend.API) error {
	expected := circuit.A
	expected.AddAssign(api, circuit.B)
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

	// 生成两个随机点
	_a := randomPointG1()
	_b := randomPointG1()
	var a, b, c bls24315.G1Affine
	a.FromJacobian(&_a)
	b.FromJacobian(&_b)

	var circuit, witness g1AddAssignAffine

	// assign the inputs
	witness.A.Assign(&a)
	witness.B.Assign(&b)

	// 计算两点相加
	_a.AddAssign(&_b)
	c.FromJacobian(&_a)
	witness.C.Assign(&c)

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
