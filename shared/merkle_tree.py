"""
shared/merkle_tree.py  —  Merkle Tree

v2.0 升級：Domain-Separated Merkle Tree

用來建立選票的 Merkle Tree 和產生驗證路徑。
CC 開票後會用這個建樹，選民可以用 get_proof() 拿到自己的驗證路徑，
然後用 verify_proof() 確認選票有沒有被計入。

v2.0 變更：
  - 葉節點：H_leaf(m) = H(0x00 || m)
  - 中間節點：H_node(L, R) = H(0x01 || L || R)
  - 奇數節點：上提 (promote) 而非複製
  - 防止 CVE-2012-2459 二次原像攻擊

v2.0 規範 §9.7
"""

import hashlib
from shared.format_utils import sha256_hex


# Domain separator 常數
DOMAIN_LEAF = b'\x00'  # 0x00 for leaf nodes
DOMAIN_NODE = b'\x01'  # 0x01 for internal nodes


def h_leaf(m_hex: str) -> str:
    """
    葉節點專用雜湊函數
    H_leaf(m) = H(0x00 || m)
    
    v2.0 規範 §9.7
    """
    m_bytes = m_hex.encode('utf-8')
    h = hashlib.sha256()
    h.update(DOMAIN_LEAF)
    h.update(m_bytes)
    return h.hexdigest()


def h_node(left: str, right: str) -> str:
    """
    中間節點專用雜湊函數
    H_node(L, R) = H(0x01 || L || R)
    
    v2.0 規範 §9.7
    """
    h = hashlib.sha256()
    h.update(DOMAIN_NODE)
    h.update(left.encode('utf-8'))
    h.update(right.encode('utf-8'))
    return h.hexdigest()


class MerkleTree:
    """
    v2.0 Domain-Separated Merkle Tree
    
    規範：
      - 葉節點：Leaf_i = H_leaf(m_i) = H(0x00 || m_i)
      - 中間節點：H_parent = H_node(L, R) = H(0x01 || L || R)
      - 奇數節點：上提而非複製
    
    m_j 為各合法選票的選票包雜湊值（hex 字串）。
    
    v2.0 規範 §9.7
    """

    def __init__(self, m_hex_list: list):
        """
        m_hex_list：各合法選票的 m 值（hex 字串）列表。
        葉節點 = H_leaf(m_j) = H(0x00 || m_j)
        """
        # 使用 domain-separated leaf hash
        self.leaves = [h_leaf(m_hex) for m_hex in m_hex_list]
        self.tree = self._build_tree(self.leaves)

    def _build_tree(self, nodes: list) -> list:
        """
        遞迴建構 Merkle Tree，回傳各層節點列表（由葉到根）
        
        v2.0 變更：奇數節點上提 (promote) 而非複製
        """
        if not nodes:
            return []
        layers = [nodes]
        current = nodes
        while len(current) > 1:
            next_layer = []
            i = 0
            while i + 1 < len(current):
                # 使用 domain-separated node hash
                parent = h_node(current[i], current[i + 1])
                next_layer.append(parent)
                i += 2
            # 奇數節點：上提而非複製
            if i < len(current):
                next_layer.append(current[i])
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
        
        v2.0：配合上提機制，不再複製末葉
        """
        proof = []
        current_index = index
        for layer_idx, layer in enumerate(self.tree[:-1]):
            # 檢查是否有兄弟節點
            if current_index % 2 == 0:
                # 當前節點在左側
                if current_index + 1 < len(layer):
                    # 有右兄弟
                    sibling_index = current_index + 1
                    position = "right"
                    proof.append({
                        "sibling": layer[sibling_index],
                        "position": position,
                    })
                # 如果沒有右兄弟，表示此節點會被上提，不需要 sibling
            else:
                # 當前節點在右側，必定有左兄弟
                sibling_index = current_index - 1
                position = "left"
                proof.append({
                    "sibling": layer[sibling_index],
                    "position": position,
                })
            current_index //= 2
        return proof

    @staticmethod
    def verify_proof(m_hex: str, proof: list, root: str) -> bool:
        """
        驗證 Merkle Proof 是否正確。
        
        v2.0 變更：
          - 起點使用 H_leaf(m) = H(0x00 || m)
          - 中間節點使用 H_node(L, R) = H(0x01 || L || R)
        
        規範：驗證起點必須為 H_leaf(m)，絕對不能用選票明文。
        m_hex：選票包雜湊值 m 的 hex 字串（未再雜湊）。
        
        v2.0 規範 §6.4
        """
        # 起點：H_leaf(m)
        current_hash = h_leaf(m_hex)
        
        # 逐層向上計算
        for step in proof:
            sibling = step["sibling"]
            if step["position"] == "right":
                # 當前在左，兄弟在右
                current_hash = h_node(current_hash, sibling)
            else:
                # 當前在右，兄弟在左
                current_hash = h_node(sibling, current_hash)
        
        return current_hash == root
