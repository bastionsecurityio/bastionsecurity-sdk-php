<?php
declare(strict_types=1);
namespace Bastion;
class BastionError extends \RuntimeException
{
    public function __construct(string $message, public readonly int $status = 0, public readonly mixed $response = null)
    {
        parent::__construct($message);
    }
}
