#!/usr/bin/env python
import angr, claripy
from angr import *

def main():

    p = angr.Project('/home/osiris/Downloads/strcmp')
    pstate = p.factory.entry_state()

    arg1 = claripy.BVS("arg1", 100*8)

    initial_state = p.factory.entry_state(args=["./strncmp", arg1])

    sim_mgr = p.factory.simulation_manager(initial_state)

    sim_mgr.explore(find=0x0804848A)

    found = sim_mgr.found[0]
    soln = found.solver.eval(arg1, cast_to=str)

    
    print(soln)


main()


