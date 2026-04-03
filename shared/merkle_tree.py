"""
shared/merkle_tree.py  —  Merkle Tree

用來建立選票的 Merkle Tree 和產生驗證路徑。
CC 開票後會用這個建樹，選民可以用 get_proof() 拿到自己的驗證路徑，
然後用 verify_proof() 確認選票有沒有被計入。
"""

from shared.format_utils import sha256_hex


class MerkleTree:
    """
    Merkle Tree。
    規範：葉節點為選票包雜湊值 m 的再雜湊，即 Leaf_i = H(m_j)。
    m_j 為各合法選票的選票包雜湊值（hex 字串）。
    """

    def __init__(self, m_hex_list: list):
        """
        m_hex_list：各合法選票的 m 值（hex 字串）列表。
        葉節點 = H(m_j)：對 m 的 hex 字串做 SHA-256。
        """
        self.leaves = [sha256_hex(m_hex.encode('utf-8')) for m_hex in m_hex_list]
        self.tree = self._build_tree(self.leaves)

    def _build_tree(self, nodes: list) -> list:
        """遞迴建構 Merkle Tree，回傳各層節點列表（由葉到根）"""
        if not nodes:
            return []
        layers = [nodes]
        current = nodes
        while len(current) > 1:
            if len(current) % 2 == 1:
                current = current + [current[-1]]
            next_layer = [
                sha256_hex((current[i] + current[i + 1]).encode('utf-8'))
                for i in range(0, len(current), 2)
            ]
            layers.append(next_layer)
            current = next_layer
        return layers

    def get_root(self) -> str:
        """取得 Merkle Root"""
        if not self.tree:
            return ""
        return self.tree[-1][0]

    def get_proof(self, index: int) -> list:
        """
        取得指定葉節點的 Merkle Proof（兄弟節點路徑）。
        回傳格式：[{"sibling": hash, "position": "left"/"right"}, ...]
        """
        proof = []
        current_index = index
        for layer in self.tree[:-1]:
            if len(layer) % 2 == 1:
                layer = layer + [layer[-1]]
            if current_index % 2 == 0:
                sibling_index = current_index + 1
                position = "right"
            else:
                sibling_index = current_index - 1
                position = "left"
            proof.append({
                "sibling":  layer[sibling_index],
                "position": position,
            })
            current_index //= 2
        return proof

    @staticmethod
    def verify_proof(m_hex: str, proof: list, root: str) -> bool:
        """
        驗證 Merkle Proof 是否正確。
        規範：驗證起點必須為 H(m)，絕對不能用選票明文。
        m_hex：選票包雜湊值 m 的 hex 字串（未再雜湊）。
        """
        current_hash = sha256_hex(m_hex.encode('utf-8'))
        for step in proof:
            sibling = step["sibling"]
            if step["position"] == "right":
                combined = current_hash + sibling
            else:
                combined = sibling + current_hash
            current_hash = sha256_hex(combined.encode('utf-8'))
        return current_hash == root
