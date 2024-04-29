package main

import (
	"github.com/consensys/gnark-crypto/ecc"
	bls24315 "github.com/consensys/gnark-crypto/ecc/bls24-315"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/native/sw_bls24315"
)

// 验证e(P,Q)=Res
type pairingBLS315 struct {
	P   sw_bls24315.G1Affine
	Q   sw_bls24315.G2Affine
	Res sw_bls24315.GT
}

func (circuit *pairingBLS315) Define(api frontend.API) error {
	//配对
	pairingRes, _ := sw_bls24315.Pair(api, []sw_bls24315.G1Affine{circuit.P}, []sw_bls24315.G2Affine{circuit.Q})
	//两个GT元素是否相等
	pairingRes.AssertIsEqual(api, circuit.Res)

	return nil
}

// 随机生成一对配对
func pairingData() (P bls24315.G1Affine, Q bls24315.G2Affine, milRes, pairingRes bls24315.GT) {

	_, _, P, Q = bls24315.Generators()
	milRes, _ = bls24315.MillerLoop([]bls24315.G1Affine{P}, []bls24315.G2Affine{Q})
	pairingRes = bls24315.FinalExponentiation(&milRes)
	return
}

func main() {
	// 生成测试数据
	P, Q, _, pairingRes := pairingData()

	// 将生成的数据创建见证人
	witness := pairingBLS315{
		P:   sw_bls24315.NewG1Affine(P),
		Q:   sw_bls24315.NewG2Affine(Q),
		Res: sw_bls24315.NewGTEl(pairingRes),
	}
	var circuit pairingBLS315

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
