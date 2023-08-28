package helper

import (
	"encoding/hex"
	"testing"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
)

func TestCheckDecrypt(t *testing.T) {
	tests := map[string]struct {
		testQuickCheckSessionKey    string
		testQuickCheckSessionKeyAlg string
		testQuickCheckDataPacket    string
	}{
		"SEIPDv1": {
			testQuickCheckSessionKey:    `038c9cb9d408074e36bac22c6b90973082f86e5b01f38b787da3927000365a81`,
			testQuickCheckSessionKeyAlg: "aes256",
			testQuickCheckDataPacket:    `d2540152ab2518950f282d98d901eb93c00fb55a3bb30b3b517d6a356f57884bac6963060ebb167ffc3296e5e99ec058aeff5003a4784a0734a62861ae56d2921b9b790d50586cd21cad45e2d84ac93fb5d8af2ce6c5`,
		},
		"SEIPDv2": {
			testQuickCheckSessionKey:    `52d777d38bb5d01e84b9b2881f0fb8e7e7cd2dbace86cb4d258c61c1b796f334`,
			testQuickCheckSessionKeyAlg: "aes256",
			testQuickCheckDataPacket:    `d26f0209020c7725b56eb4aa8032bb8583003d6491e0867dd8f1b74900e8d1c173f46da63c2ec75c89e259aaccbe51ae95c8ac3e950d5045bfca4fce33faa8cf22d577a443b1a49c168d080356691a8953a322c87ec939664b8f406fe4ecbfd8c93610862da36cc815e2d5e919aefe07c5`,
		},
		"SEIPDv2_large": {
			testQuickCheckSessionKey:    `bf910864856e7bcaeabd82edc27fac687af1dd166b779028c3bbaefd574156d4`,
			testQuickCheckSessionKeyAlg: "aes256",
			testQuickCheckDataPacket:    `d2ea0209020cc3d915192d75065eb5da4ee2f2ce1da3ce441754eae4f48a3d3fa7e495cf1b1f5fcb3e2784ded10f5bc691b151fda867406d8f159065df28db844bc548d2195958ea2412ec50bdea39343ad4efe3607d48937bd98c2b7c2695dbe9fe3f7f6a6e67be6491dbfaa4272cd6a4d0387f71ec78783133968793631d305fedc5776e17bff413b8f9c17e5d55e94da1fd735a7bb6b3a4880f8541e3efa5969c220cf609fe3ed0d75ef83a7819ff542eafe596ccc0867bf70dc98e666e36016e119882f34fb950594040e2fd03096bb11c571d87bc4d08f9d10903b4c46dd9afd26724695bdb9e75e948d749c473e700c17f198c345ddac94c48438d1a3ed643483524361a96d79ead8fe3ae3f0015fdca0c82bd5e7f9c06c4efe16f26b0bf89807d04ee27f55eda2a10e0f09af48a2a740b8f82aae14cacd17183fbc64cdbac102b21c6d89470e0f5bf0073ffc48871600530af2de36a93545004fb445700fe0c7add0756247d1457ff60e3de48ce551be7ee1da0b3b8ef996188a8be304213e59a95b33d4f95d33a923e93dce3a287c35b8e9dd01b0acded222666bb20d6b2f50eaf906b4a74f09e3bc4126da5589b0044425e068daddffab50633fe3c1bb29778faaae5e54d4b4e779d94ff023ff5eb8de12510fff2483ec3e51ca92dd07eb499a5ec32bd1033195bad2c944d76c2d01c9b27c1497be830a7b389e1cb1b1fdabfb2ec35638d83502c8b07bc9fb104b16ffd328b58c002ac758170aa42f63f77d83deda1018677621b8da0300930668578dec42d048aa79dba7d83d9e6516efe10fdb6e87da06c72ad5566b7e70d510d671dc21b5669ec1144c53822fc3c22e76623ed872560b2b374c204abb410478cdaed169f35b78889785d86d46b84fe50a73ef89ae237439e82b59fac01282b8ecdac63ae251d1334e7f97be83ffceadf347b1fe6bcfcd5d06cf73cdb27191ba5e9c6aea040486ef7cff3565985e50639a7defce695af40a5350f1d084d58618488075a4122e64910f103498fc3f2ccf8d37d48ddd61fca3f7be4e5e88549f53b94bfb3613a88a77549ada595ea041fffc5e6aae30bdf4a7323965cd6fe69f3abf9eb7380e0cceaed21fe52f5308dc762837bdccebaffa82910db071507ee47bb1b92295c6fde0e16e3fd6c407f35ff1c973e4de4217fc33424e22ea228a478ff3b35eabb1245732e423263ca890f3c3ca063846f69390ec7790f7f7af2341b003065750f2fc9859de92104ce1d8f2c178bab4745153685a1c86cc3fe751613af9ac8285632bf5db647b54300031be92b8725efb9d3469ddcff3fbc1570aebde2d8eed13ca08680b2120faae59b30a4b768a6b5f1944a8e482576fcdf629eb7a49c69e1d17af189f9ef18c3944def6e503e0fb02c6e7cbda9144a71c5238e7795ae7c1d5c9d6453ee3de62aab60bf7bad901de03d8eb05d6be446206fa4e65d6873177195322bd032ce1d64f3f20d864e73cb2e26c0e49aa84aa20a130d1dcfe27592956e69c9b7cb5088c9791f93c13b3cbfbd8073c137db6ba008cbadd29100839198cd3b25f58dd2e9734336cb06bac377b35451cb44a88a7675913ba92c7055fb9aecdd2c68428d81f7616d7a16bce58e23e03d4b893c6bb182fbae575b6df6e38180b29932a9f8c2d8231edf25c260edc1e90417ead711620ab872`,
		},
	}
	for name, data := range tests {
		testData := data
		t.Run(name, func(t *testing.T) {
			sessionKeyData, err := hex.DecodeString(testData.testQuickCheckSessionKey)
			if err != nil {
				t.Error(err)
			}
			dataPacket, err := hex.DecodeString(testData.testQuickCheckDataPacket)
			if err != nil {
				t.Error(err)
			}
			sessionKey := &crypto.SessionKey{
				Key:  sessionKeyData,
				Algo: testData.testQuickCheckSessionKeyAlg,
			}
			ok, err := QuickCheckDecrypt(sessionKey, dataPacket)
			if err != nil {
				t.Error(err)
			}
			if !ok {
				t.Error("should be able to decrypt")
			}

			sessionKey.Key[0] += 1
			ok, err = QuickCheckDecrypt(sessionKey, dataPacket)
			if err != nil {
				t.Error(err)
			}
			if ok {
				t.Error("should no be able to decrypt")
			}
		})
	}
}
