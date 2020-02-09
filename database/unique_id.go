package database

import (
  "encoding/base32"
  "crypto/rand"
)

// A unique id is just 128 random bytes.
type UniqueId [16]byte

func NewUniqueId() (UniqueId, error) {
  id := UniqueId{}

  _, err := rand.Read(id[:])
  if err != nil {
    return UniqueId{}, err
  }

  return id, nil
}

func (id *UniqueId) String() string {
  id[:]
}
