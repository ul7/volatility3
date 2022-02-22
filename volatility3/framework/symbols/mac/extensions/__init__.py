# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

from typing import Generator, Iterable, Optional, Set, Tuple

import logging

from volatility3.framework import constants, objects, renderers
from volatility3.framework import exceptions, interfaces
from volatility3.framework.objects import utility
from volatility3.framework.renderers import conversion
from volatility3.framework.symbols import generic

vollog = logging.getLogger(__name__)

class proc(generic.GenericIntelProcess):

    def get_task(self):
        return self.task.dereference().cast("task")

    def add_process_layer(self, config_prefix: str = None, preferred_name: str = None) -> Optional[str]:
        """Constructs a new layer based on the process's DTB.

        Returns the name of the Layer or None.
        """
        parent_layer = self._context.layers[self.vol.layer_name]

        if not isinstance(parent_layer, interfaces.layers.TranslationLayerInterface):
            raise TypeError("Parent layer is not a translation layer, unable to construct process layer")

        try:
            dtb = self.get_task().map.pmap.pm_cr3
        except exceptions.InvalidAddressException:
            return None

        if preferred_name is None:
            preferred_name = f'{self.vol.layer_name}_Process{self.p_pid}'

        # Add the constructed layer and return the name
        return self._add_process_layer(self._context, dtb, config_prefix, preferred_name)

    def get_map_iter(self) -> Iterable[interfaces.objects.ObjectInterface]:
        try:
            task = self.get_task()
        except exceptions.InvalidAddressException:
            return

        try:
            current_map = task.map.hdr.links.next
        except exceptions.InvalidAddressException:
            return

        seen: Set[int] = set()

        for _ in range(task.map.hdr.nentries):
            if (not current_map or
                current_map.vol.offset in seen or
                not self._context.layers[task.vol.native_layer_name].is_valid(current_map.dereference().vol.offset, current_map.dereference().vol.size)):

                vollog.log(constants.LOGLEVEL_VVV, "Breaking process maps iteration due to invalid state.")
                break

            # ZP_POISON value used to catch programming errors
            if current_map.links.start == 0xdeadbeefdeadbeef or current_map.links.end == 0xdeadbeefdeadbeef:
                break

            yield current_map
            seen.add(current_map.vol.offset)
            current_map = current_map.links.next

    ######
    # ikelos: this breaks with multi threading on, but works with it disabled
    # with multi threading on, it throws that same error about v4 pickle stuff that linux originally did
    # the fix for linux was to call int() so that we were not returning vol objects.
    # I call int() on these and the code works nearly 1-1 with the linux one so I am very confused
    ######
    def get_process_memory_sections(self,
                                    context: interfaces.context.ContextInterface,
                                    config_prefix: str,
                                    rw_no_file: bool = False) -> Generator[Tuple[int, int], None, None]:
        """Returns a list of sections based on the memory manager's view of
        this task's virtual memory."""
        for vma in self.get_map_iter():
            start = int(vma.links.start)
            end = int(vma.links.end)

            if (
                rw_no_file
                and (
                    vma.get_perms() != "rw"
                    or vma.get_path(context, config_prefix) != ""
                )
                and vma.get_special_path() != "[heap]"
            ):
                continue

            yield (start, end - start)


class fileglob(objects.StructType):

    def get_fg_type(self):
        ret = None

        if self.has_member("fg_type"):
            ret = self.fg_type
        elif self.fg_ops != 0:
            try:
                ret = self.fg_ops.fo_type
            except exceptions.InvalidAddressException:
                pass

        if ret:
            ret = str(ret.description).replace("DTYPE_", "")

        return ret


class vm_map_object(objects.StructType):

    def get_map_object(self):
        if self.has_member("vm_object"):
            return self.vm_object
        elif self.has_member("vmo_object"):
            return self.vmo_object

        raise AttributeError("vm_map_object -> get_object")


class vnode(objects.StructType):

    def _do_calc_path(self, ret, vnodeobj, vname):
        if vnodeobj is None:
            return

        if vname:
            try:
                ret.append(utility.pointer_to_string(vname, 255))
            except exceptions.InvalidAddressException:
                return

        if int(vnodeobj.v_flag) & 0x000001 == 0 or int(vnodeobj.v_mount) == 0:
            try:
                parent = vnodeobj.v_parent
                parent_name = parent.v_name
            except exceptions.InvalidAddressException:
                return

            self._do_calc_path(ret, parent, parent_name)

        elif int(vnodeobj.v_mount.mnt_vnodecovered) != 0:
            self._do_calc_path(ret, vnodeobj.v_mount.mnt_vnodecovered, vnodeobj.v_mount.mnt_vnodecovered.v_name)

    def full_path(self):
        if self.v_flag & 0x000001 != 0 and self.v_mount != 0 and self.v_mount.mnt_flag & 0x00004000 != 0:
            ret = b"/"
        else:
            elements = []
            self._do_calc_path(elements, self, self.v_name)
            elements.reverse()

            files = [e.encode("utf-8") for e in elements]
            ret = b"/".join(files)
            if ret:
                ret = b"/" + ret

        return ret.decode("utf-8")


class vm_map_entry(objects.StructType):

    def is_suspicious(self, context, config_prefix):
        """Flags memory regions that are mapped rwx or that map an executable
        not back from a file on disk."""
        ret = False

        perms = self.get_perms()

        if perms == "rwx":
            ret = True

        elif perms == "r-x" and self.get_path(context, config_prefix) == "":
            ret = True

        return ret

    def get_perms(self):
        permask = "rwx"
        return "".join(
            permask[ctr] if (self.protection & i) == i else "-"
            for (ctr, i) in enumerate([1, 3, 5])
        )

    def get_range_alias(self):
        return (
            int(self.alias)
            if self.has_member("alias")
            else int(self.vme_offset) & 0xFFF
        )

    def get_special_path(self):
        check = self.get_range_alias()

        if 0 < check < 10:
            return "[heap]"
        elif check == 30:
            return "[stack]"
        else:
            return ""

    def get_path(self, context, config_prefix):
        node = self.get_vnode(context, config_prefix)

        if type(node) == str and node == "sub_map":
            return node
        elif node:
            path = []
            seen: Set[int] = set()
            while node and node.vol.offset not in seen:
                try:
                    v_name = utility.pointer_to_string(node.v_name, 255)
                except exceptions.InvalidAddressException:
                    break

                path.append(v_name)
                if len(path) > 1024:
                    break

                seen.add(node.vol.offset)

                node = node.v_parent

            path.reverse()
            return "/" + "/".join(path)
        else:
            return ""

    def get_object(self):
        if self.has_member("vme_object"):
            return self.vme_object
        elif self.has_member("object"):
            return self.object

        raise AttributeError("vm_map_entry -> get_object: Unable to determine object")

    def get_offset(self):
        if self.has_member("vme_offset"):
            return self.vme_offset
        elif self.has_member("offset"):
            return self.offset

        raise AttributeError("vm_map_entry -> get_offset: Unable to determine offset")

    def get_vnode(self, context, config_prefix):
        if self.is_sub_map == 1:
            return "sub_map"

        # based on find_vnode_object
        vnode_object = self.get_object().get_map_object()
        if vnode_object == 0:
            return None

        found_end = False
        while not found_end:
            try:
                tmp_vnode_object = vnode_object.shadow.dereference()
            except exceptions.InvalidAddressException:
                break

            if tmp_vnode_object.vol.offset == 0:
                found_end = True
            else:
                vnode_object = tmp_vnode_object

        if vnode_object.vol.offset == 0:
            return None

        try:
            pager = vnode_object.pager
            if pager == 0:
                return None

            ops = pager.mo_pager_ops.dereference()
        except exceptions.InvalidAddressException:
            return None

        found = any(
            sym.split(constants.BANG)[1] in ["vnode_pager_ops", "_vnode_pager_ops"]
            for sym in context.symbol_space.get_symbols_by_location(ops.vol.offset)
        )

        if found:
            vpager = context.object(config_prefix + constants.BANG + "vnode_pager",
                                    layer_name = vnode_object.vol.native_layer_name,
                                    offset = vnode_object.pager)
            return vpager.vnode_handle
        else:
            return None


class socket(objects.StructType):

    def get_inpcb(self):
        try:
            ret = self.so_pcb.dereference().cast("inpcb")
        except exceptions.InvalidAddressException:
            ret = None

        return ret

    def get_family(self):
        return self.so_proto.pr_domain.dom_family

    def get_protocol_as_string(self):
        proto = self.so_proto.pr_protocol

        if proto == 17:
            return "UDP"
        elif proto == 6:
            return "TCP"
        else:
            return ""

    def get_state(self):
        ret = ""

        if self.so_proto.pr_protocol == 6:
            inpcb = self.get_inpcb()
            if inpcb is not None:
                ret = inpcb.get_tcp_state()

        return ret

    def get_connection_info(self):
        inpcb = self.get_inpcb()

        if inpcb is None:
            return None
        elif self.get_family() == 2:
            return inpcb.get_ipv4_info()
        else:
            return inpcb.get_ipv6_info()

    def get_converted_connection_info(self):
        return (
            conversion.convert_network_four_tuple(self.get_family(), vals)
            if (vals := self.get_connection_info())
            else None
        )


class inpcb(objects.StructType):

    def get_tcp_state(self):
        tcp_states = ("CLOSED", "LISTEN", "SYN_SENT", "SYN_RECV", "ESTABLISHED", "CLOSE_WAIT", "FIN_WAIT1", "CLOSING",
                      "LAST_ACK", "FIN_WAIT2", "TIME_WAIT")

        try:
            tcpcb = self.inp_ppcb.dereference().cast("tcpcb")
        except exceptions.InvalidAddressException:
            return ""

        state_type = tcpcb.t_state
        return (
            tcp_states[state_type]
            if state_type and state_type < len(tcp_states)
            else ""
        )

    def get_ipv4_info(self):
        try:
            lip = self.inp_dependladdr.inp46_local.ia46_addr4.s_addr
        except exceptions.InvalidAddressException:
            return None

        lport = self.inp_lport

        try:
            rip = self.inp_dependfaddr.inp46_foreign.ia46_addr4.s_addr
        except exceptions.InvalidAddressException:
            return None

        rport = self.inp_fport

        return [lip, lport, rip, rport]

    def get_ipv6_info(self):
        try:
            lip = self.inp_dependladdr.inp6_local.member(attr = '__u6_addr').member(attr = '__u6_addr32')
        except exceptions.InvalidAddressException:
            return None

        lport = self.inp_lport

        try:
            rip = self.inp_dependfaddr.inp6_foreign.member(attr = '__u6_addr').member(attr = '__u6_addr32')
        except exceptions.InvalidAddressException:
            return None

        rport = self.inp_fport

        return [lip, lport, rip, rport]


class queue_entry(objects.StructType):

    def walk_list(self,
                  list_head: interfaces.objects.ObjectInterface,
                  member_name: str,
                  type_name: str,
                  max_size: int = 4096) -> Iterable[interfaces.objects.ObjectInterface]:
        """
        Walks a queue in a smear-aware and smear-resistant manner

        smear is detected by:
            - the max_size parameter sets an upper bound
            - each seen entry is only allowed once

        attempts to work around smear:
            - the list is walked in both directions to help find as many elements as possible

        Args:
            list_head   - the head of the list
            member_name - the name of the embedded list member
            type_name   - the type of each element in the list
            max_size    - the maximum amount of elements that will be returned

        Returns:
            Each instance of the queue cast as "type_name" type
        """

        yielded = 0

        seen = set()

        for attr in ['next', 'prev']:
            try:
                n = getattr(self, attr).dereference().cast(type_name)

                while n is not None and n.vol.offset != list_head:
                    if n.vol.offset in seen:
                        break

                    yield n

                    seen.add(n.vol.offset)

                    yielded += 1
                    if yielded == max_size:
                        return

                    n = getattr(n.member(attr = member_name), attr).dereference().cast(type_name)

            except exceptions.InvalidAddressException:
                pass


class ifnet(objects.StructType):

    def sockaddr_dl(self):
        if self.has_member("if_lladdr"):
            try:
                val = self.if_lladdr.ifa_addr.dereference().cast("sockaddr_dl")
            except exceptions.InvalidAddressException:
                val = None
        else:
            try:
                val = self.if_addrhead.tqh_first.ifa_addr.dereference().cast("sockaddr_dl")
            except exceptions.InvalidAddressException:
                val = None

        return val


# this is used for MAC addresses
class sockaddr_dl(objects.StructType):

    def __str__(self):
        ret = ""

        if self.sdl_alen > 14:
            return ret

        for i in range(self.sdl_alen):
            try:
                e = self.sdl_data[self.sdl_nlen + i]
            except IndexError:
                break

            e = e.cast("unsigned char")

            ret += f"{e:02X}:"

        if ret and ret[-1] == ":":
            ret = ret[:-1]

        return ret


class sockaddr(objects.StructType):

    def get_address(self):
        ip = ""

        family = self.sa_family
        if family == 2:  # AF_INET
            addr_in = self.cast("sockaddr_in")
            ip = conversion.convert_ipv4(addr_in.sin_addr.s_addr)

        elif family == 30:  # AF_INET6
            addr_in6 = self.cast("sockaddr_in6")
            ip = conversion.convert_ipv6(addr_in6.sin6_addr.member(attr = "__u6_addr").member(attr = "__u6_addr32"))

        elif family == 18:  # AF_LINK
            addr_dl = self.cast("sockaddr_dl")
            ip = str(addr_dl)

        return ip


class sysctl_oid(objects.StructType):

    def get_perms(self) -> str:
        """
        Returns the actions allowed on the node

        Args: None

        Returns:
            A combination of:
                R - readable
                W - writeable
                L - self handles locking
        """
        checks = [0x80000000, 0x40000000, 0x00800000]
        perms = ["R", "W", "L"]

        return "".join(
            perms[i] if c & self.oid_kind else "-" for (i, c) in enumerate(checks)
        )

    def get_ctltype(self) -> str:
        """
        Returns the type of the sysctl node

        Args: None

        Returns:
            One of:
                CTLTYPE_NODE
                CTLTYPE_INT
                CTLTYPE_STRING
                CTLTYPE_QUAD
                CTLTYPE_OPAQUE
                an empty string for nodes not in the above types

        Based on sysctl_sysctl_debug_dump_node
        """
        types = {1: 'CTLTYPE_NODE', 2: 'CTLTYPE_INT', 3: 'CTLTYPE_STRING', 4: 'CTLTYPE_QUAD', 5: 'CTLTYPE_OPAQUE'}

        ctltype = self.oid_kind & 0xf

        return types[ctltype] if 0 < ctltype < 6 else ""


class kauth_scope(objects.StructType):

    def get_listeners(self):
        for listener in self.ks_listeners:
            if listener != 0 and listener.kll_callback != 0:
                yield listener
