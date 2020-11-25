<?php

namespace App\Repository;

use App\Entity\User;
use Doctrine\Persistence\ManagerRegistry;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\PasswordUpgraderInterface;
use Doctrine\Bundle\DoctrineBundle\Repository\ServiceEntityRepository;
use League\OAuth2\Client\Provider\GithubResourceOwner;
use Symfony\Component\Security\Core\Exception\UnsupportedUserException;

/**
 * @method User|null find($id, $lockMode = null, $lockVersion = null)
 * @method User|null findOneBy(array $criteria, array $orderBy = null)
 * @method User[]    findAll()
 * @method User[]    findBy(array $criteria, array $orderBy = null, $limit = null, $offset = null)
 */
class UserRepository extends ServiceEntityRepository implements PasswordUpgraderInterface
{
    public function __construct(ManagerRegistry $registry)
    {
        parent::__construct($registry, User::class);
    }

    /**
     * Used to upgrade (rehash) the user's password automatically over time.
     */
    public function upgradePassword(UserInterface $user, string $newEncodedPassword): void
    {
        if (!$user instanceof User) {
            throw new UnsupportedUserException(sprintf('Instances of "%s" are not supported.', \get_class($user)));
        }

        $user->setPassword($newEncodedPassword);
        $this->_em->persist($user);
        $this->_em->flush();
    }

    public function findOrCreateFromGithubOauth(GithubResourceOwner $owner)
    {
        /** @var User|null $user */
        $user = $this->createQueryBuilder('u')
        ->where('u.githubId = :githubId')
        ->orWhere('u.email = :email')
        ->setParameters([
            ':email'    =>  $owner->getEmail(),
            ':githubId' =>  $owner->getId(),
        ])
        ->getQuery()
        ->getOneOrNullResult();

        if ($user) {
            if ($user->getGithubId() === null) {
                $user->setGithubId($owner->getId());
                $this->getEntityManager()->flush();
            }

            return $user;
        }

        $user = (new User)
            ->setRoles(['ROLE_USER'])
            ->setGithubId($owner->getId())
            ->setEmail($owner->getEmail());
            $em = $this->getEntityManager();
            $em->persist($user);
            $em->flush();

            return $user;
    }
}
