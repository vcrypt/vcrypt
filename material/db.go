package material

// DB interface for loading and storing material.
type DB interface {
	// LoadMaterial retrieves Material data from a backing store.
	LoadMaterial([]byte) (*Material, error)

	// StoreMaterial saves Material data to a backing store.
	StoreMaterial(*Material) error
}
