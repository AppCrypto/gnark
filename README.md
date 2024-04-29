根据gnark写的一点测试用例
使用方法：将本仓库复制到本地
cd gnark/examples
文件夹1-------两点相加等于第三点（go run main.go）

文件夹2-------双线性配对e(G1,G2)=GT（go run main.go）

文件夹3-------判断C=G*R，G是基点（go run main.go）

文件夹1-------判断C=A*B，ABC为三点（go run main.go）

gnark/std/algebra/native下sw_bls12377和sw_bls24315为两条可用曲线
g1.go处理G1上的操作，点加，点乘
g2.go处理G2上的操作，点加，点乘
pairing.go处理配对
gnark/std/algebra/native下fields_bls12377和fields_bls24315
 GT = fields_bls24315.E24  为GT操作
