from abc import ABC, abstractmethod
from .blockchain import Block, Blockchain

class Consensus(ABC):
    """Абстрактный базовый класс для алгоритмов консенсуса."""

    @abstractmethod
    def validate_block(self, block: Block, chain: Blockchain) -> bool:
        """Валидирует блок в соответствии с правилами консенсуса."""
        pass


class ProofOfWork(Consensus):
    """Proof-of-Work (PoW) консенсус."""

    def __init__(self, difficulty: int):
        self.difficulty = difficulty

    def validate_block(self, block: Block, chain: Blockchain) -> bool:
        """Валидирует блок, проверяя PoW."""
        block_hash = block.compute_hash()
        
        # Проверяем предыдущий хеш
        previous_hash_matches = (block.previous_hash == chain.get_block_by_index(block.index - 1).hash if block.index > 0 else True)

        # Проверяем сложность хеша
        difficulty_check = block_hash.startswith('0' * self.difficulty)
        
        return difficulty_check and previous_hash_matches
    
    def adjust_difficulty(self, chain: Blockchain):
        """Регулирует сложность в зависимости от времени, затраченного на добычу последнего блока."""
        last_block = chain.last_block
        if last_block.index > 0:
            previous_block = chain.get_block_by_index(last_block.index - 1)
            time_diff = last_block.timestamp - previous_block.timestamp
            if time_diff < self.target_block_time / 2:
                self.difficulty += 1
            elif time_diff > self.target_block_time * 2:
                self.difficulty -= 1 if self.difficulty > 1 else 0 # difficulty не может быть меньше 1


# class ProofOfStake(Consensus): #  и т.д. - слишком сложная и муторная херня обойдемся без неё