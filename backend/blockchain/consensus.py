from abc import ABC, abstractmethod
from .blockchain import Block # Импортируйте ваш класс Block

class Consensus(ABC):
    @abstractmethod
    def validate_block(self, block: Block, chain: 'Blockchain') -> bool:
        """
        Валидирует блок в соответствии с правилами консенсуса.

        Args:
            block: Блок для валидации.
            chain: Экземпляр блокчейна (для доступа к предыдущим блокам и т.д.)

        Returns:
            True, если блок валиден, False иначе.
        """
        pass


class ProofOfWork(Consensus):
    def __init__(self, difficulty: int):
        self.difficulty = difficulty

    def validate_block(self, block: Block, chain: 'Blockchain') -> bool:
        """
        Валидирует блок, проверяя proof-of-work.
        """
        block_hash = block.compute_hash()
        return (block_hash.startswith('0' * self.difficulty) and
                chain.last_block.hash == block.previous_hash and  # Добавленная проверка
                block.previous_hash == chain.get_block_by_index(block.index-1).hash if block.index > 0 else True)



class ProofOfStake(Consensus):  # Пример PoS (упрощенный)
    def __init__(self, validators: list):
      self.validators = validators

    def validate_block(self, block: Block, chain: 'Blockchain') -> bool:
        """
        Валидирует блок, проверяя, является ли создатель блока валидатором.
        В реальном PoS требуется более сложная логика, связанная со стейкингом,
        выбором валидатора и т.д.
        """
        # Здесь должна быть логика проверки PoS (например, проверка подписи, стейка и т.д.)
        # Этот пример просто проверяет, есть ли создатель блока в списке валидаторов
        # Замените это вашей реальной логикой PoS
        creator = block.transactions[0]['sender'] if block.transactions else None # предполагаем, что первая транзакция - создание блока
        return creator in self.validators