import sys


class Colors:
    G = '\033[92m'  # green
    Y = '\033[93m'  # yellow
    B = '\033[94m'  # blue
    R = '\033[91m'  # red
    W = '\033[0m'  # white

    # noinspection PyBroadException
    @staticmethod
    def color(no_color: bool):
        if not no_color:

            is_windows = sys.platform.startswith('win')

            if is_windows:
                try:
                    import win_unicode_console
                    import colorama
                    win_unicode_console.enable()
                    colorama.init()
                except:
                    print("To use colored version in Windows: 'pip install win_unicode_console colorama'")
                    print("You can use --no-color to use non colored output")
        else:
            Colors.G = Colors.Y = Colors.B = Colors.R = Colors.W = ''
