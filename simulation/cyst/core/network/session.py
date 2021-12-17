import uuid

from collections.abc import Iterable
from typing import List, Tuple, Optional
from netaddr import IPAddress

from cyst.api.network.node import Node
from cyst.api.network.session import Session

from cyst.core.network.elements import Hop, Endpoint, Resolver


# The session represents an existing chain of connections, which can be traversed without authorization by its owner
class SessionImpl(Session):
    def __init__(self, owner: str, parent: Session = None, path: List[Hop] = None, resolver: Optional[Resolver] = None) -> None:
        self._id = uuid.uuid4()
        # TODO Remove owners. They don't work and the are not needed
        if not owner:
            raise Exception("Cannot create a session without an owner")

        self._owner = owner
        self._parent: Optional[SessionImpl] = None
        if parent:
            self._parent = SessionImpl.cast_from(parent)

        # TODO: Session ownership is a dead-end concept and needs to be removed
        # if self._parent and parent.owner != self._owner:
        #     raise Exception("Cannot link sessions with different owners")

        if not path:
            raise Exception("Cannot create a session without a path")

        self._path: List[Hop] = path

        # Resolve all IP addresses if possible
        for hop in self._path:
            if not hop.src.ip and resolver:
                hop.src.ip = resolver.resolve_ip(hop.src.id, hop.src.port)

            if not hop.dst.ip and resolver:
                hop.dst.ip = resolver.resolve_ip(hop.dst.id, hop.dst.port)

        if self._parent and self._parent.endpoint == self._path[-1].dst:
            raise Exception("Cannot create a session sharing an endpoint with a parent")

    class ForwardIterator(Iterable):
        def __init__(self, session: 'SessionImpl') -> None:
            self._session = session
            self._path_index = 0
            if session.parent:
                self._parent_iterator = SessionImpl.cast_from(session.parent).forward_iterator
            else:
                self._parent_iterator = None
            self._parent_traversed = False

        def has_next(self) -> bool:
            if self._parent_iterator and self._parent_iterator.has_next():
                return True

            if self._path_index != len(self._session.path_id):
                return True

            return False

        def __iter__(self):
            return self

        def __next__(self) -> Hop:
            if self._parent_traversed or not self._session.parent:
                if self._path_index != len(self._session.path_id):
                    result = self._session.path_id[self._path_index]
                    self._path_index += 1
                    return result
                else:
                    raise StopIteration
            else:
                if self._parent_iterator.has_next():
                    return self._parent_iterator.__next__()
                else:
                    self._parent_traversed = True
                    return self.__next__()

    class ReverseIterator(Iterable):
        def __init__(self, session: 'SessionImpl') -> None:
            self._session = session
            self._path_index = len(self._session.path_id) - 1
            if session.parent:
                self._parent_iterator = SessionImpl.cast_from(session.parent).reverse_iterator
            else:
                self._parent_iterator = None
            self._parent_traversing = False

        def has_next(self) -> bool:
            if self._path_index >= 0:
                return True

            elif self._parent_iterator:
                return self._parent_iterator.has_next()

            return False

        def __iter__(self):
            return self

        def __next__(self) -> Hop:
            if self._path_index >= 0:
                result = self._session.path_id[self._path_index]
                self._path_index -= 1
                return result.swap()
            else:
                if not self._parent_traversing:
                    self._parent_traversing = True
                    return self.__next__()
                else:
                    if self._parent_iterator.has_next():
                        result = self._parent_iterator.__next__()
                        return result
                    else:
                        raise StopIteration

    # ------------------------------------------------------------------------------------------------------------------
    # Session interface
    @property
    def owner(self) -> str:
        return self._owner

    @property
    def id(self) -> str:
        return str(self._id)

    @property
    def parent(self) -> Session:
        return self._parent

    @property
    def path(self) -> List[Tuple[Optional[IPAddress], Optional[IPAddress]]]:
        return [(x.src.ip, x.dst.ip) for x in self._path]

    @property
    def end(self) -> Optional[IPAddress]:
        return self._path[-1].dst.ip

    @property
    def start(self) -> Optional[IPAddress]:
        if self._parent:
            return self._parent.start
        else:
            return self._path[0].src.ip

    def terminates_at(self, node: Node) -> bool:
        end_ip = self.end
        for iface in node.interfaces:
            if iface.ip == end_ip:
                return True
        return False

    # ------------------------------------------------------------------------------------------------------------------

    @property
    def forward_iterator(self) -> ForwardIterator:
        return SessionImpl.ForwardIterator(self)

    @property
    def reverse_iterator(self) -> ReverseIterator:
        return SessionImpl.ReverseIterator(self)

    # Endpoint is a destination node of the last path hop
    @property
    def endpoint(self) -> Endpoint:
        return self._path[-1].dst

    @property
    def startpoint(self) -> Endpoint:
        if self._parent:
            return self._parent.startpoint
        else:
            return self._path[0].src

    @property
    def path_id(self) -> List[Hop]:
        return self._path

    def __str__(self) -> str:
        full_path = self.path
        parent = self._parent
        while parent:
            full_path = parent.path + full_path
            parent = parent.parent

        path_repr = [str(self.start)]
        path_repr.extend([str(x[1]) for x in full_path])
        return "[ID: {}, Owner: {}, Path: {}]".format(self.id, self.owner, path_repr)

    def __repr__(self) -> str:
        full_path = self.path_id
        parent = self._parent
        while parent:
            full_path = parent.path_id + full_path
            parent = parent.parent
        return "[ID: {}, Owner: {}, Path: {}]".format(self.id, self.owner, full_path)

    def __eq__(self, other: 'SessionImpl') -> bool:
        # Comparing to None, everything is False
        if not other:
            return False

        # Hard type check
        if not isinstance(other, SessionImpl):
            return False

        # Owner comparison - to be removed
        if self.owner != other.owner:
            return False

        # If one session has parent and the other does not they are not the same
        # Also, looking for a better way to write it
        if (self.parent is None and other.parent is not None) or \
           (self.parent is not None and other.parent is None):
            return False

        # If their parents don't match, they are not the same
        if self.parent and self.parent != other.parent:
            return False

        # If their paths don't match, they are not the same
        if self._path != other._path:
            return False

        return True

    @staticmethod
    def cast_from(o: Session) -> 'SessionImpl':
        if isinstance(o, SessionImpl):
            return o
        else:
            raise ValueError("Malformed underlying object passed with the Session interface")