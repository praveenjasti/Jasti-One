import psutil

def memory_summary():
    vm = psutil.virtual_memory()
    return f"{vm.percent}% used · {vm.available / (1024**3):.1f} GB available of {vm.total / (1024**3):.1f} GB"
