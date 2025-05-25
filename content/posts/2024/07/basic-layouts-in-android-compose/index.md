---
title: "Android-Compose中的基本布局"
date: 2024-07-12
categories: 
  - "安卓"
  - "web-develop"
tags: 
  - "android"
  - "app"
---

## 目标

构建一个健康应用，这款应用包含两个版块，一个列出了**收藏合集**，另一个列出了**各种体育锻炼**。具体如下图所示，包括竖屏和横屏的适配

![](./images/image-28.png)

![](./images/image-29.png)

## 主要内容

- 借助修饰符扩充可组合项

- 通过 Column 和 LazyRow 等标准布局组件定位可组合子项

- 通过对齐方式和排列方式更改可组合子项在父项中的位置

- 借助 **Scaffold** 和 **Bottom Navigation** 等 Material 可组合项创建详细布局

- 使用**槽位 API** 构建灵活的可组合项

- 为不同的屏幕配置构建布局

## 结构分析

![](./images/image-31.png)

总体来说可以将应用分为**内容**和**导航栏**两个部分

在内容部分又可以分**为搜索栏、收藏栏以及运动收集网格**

![](./images/image-32.png)

### 搜索栏

```
@Composable
fun SearchBar(modifier: Modifier=Modifier)
{
    TextField(value = "",
        onValueChange = {},
        modifier= modifier
            .fillMaxWidth()
            .heightIn(min = 56.dp),
        leadingIcon = {
            Icon(painter = painterResource(id = R.drawable.search), contentDescription = null )
        },
        colors = TextFieldDefaults.colors(
            unfocusedLabelColor = MaterialTheme.colorScheme.surface,
            focusedContainerColor = MaterialTheme.colorScheme.surface,
        ),
        placeholder = {
            Text(text = stringResource(R.string.search))
        }
    )
}
```

![](data:image/png;base64,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)

图标是在[Browse Fonts - Google Fonts](https://fonts.google.com/)这里下载的。总体代码还是比较简单的，这里先不涉及具体的文本处理。

### **收藏栏**

首先要分析每个元素的具体结构。

![](./images/image-33.png)

可以看到，要对图片进行裁剪，并且在图片下面要对齐相应的文字。

使用modifier的clip对图片进行裁剪，并且可能会出现裁剪之后有残缺，又用了ContentScale对图片进行适当缩放来填满clip的形状

![](./images/image-38.png)

```
@Composable
fun AlignYourBodyElement(
    modifier: Modifier=Modifier,
    @DrawableRes drawable:Int,
    @StringRes text:Int
)
{
    Column(
        horizontalAlignment = Alignment.CenterHorizontally,
        modifier = modifier
    ) {
        Image(painter = painterResource(id = drawable),
            contentDescription =null ,
            modifier= Modifier
                .size(88.dp)
                .clip(CircleShape),
            contentScale = ContentScale.Crop

        )
        Text(text = stringResource(id = text),
            modifier=Modifier.paddingFromBaseline(top = 24.dp, bottom = 8.dp)
        )
    }
}
```

这里涉及到了**@DrawableRes**和**@StringRes**两个修饰符，显式规定了传入参数的类型可以被当作resource处理。类似于 **R.string.username** 这样的资源引用方式，实际上在程序中是以**Int**数字类型进行传递的（可以调试查看）。添加注解后，编译器会**提前检查资源**是否合法存在，防止错误的资源类型传递。

剩下的就是将每个元素进行**横向排列**  

![](./images/image-34.png)

```
@Composable
fun AlignYourBodyRow(modifier: Modifier=Modifier)
{
    val alignYourBodyData=
        listOf(
            AlignYourBodyData(R.drawable.tomcat,R.string.username),
            AlignYourBodyData(R.drawable.tomcat,R.string.username),
            AlignYourBodyData(R.drawable.tomcat,R.string.username),
            AlignYourBodyData(R.drawable.tomcat,R.string.username),
            AlignYourBodyData(R.drawable.tomcat,R.string.username),
    )

    LazyRow(
        modifier=modifier,
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        contentPadding = PaddingValues(horizontal = 16.dp)
    ){
        items(alignYourBodyData){
            item-> AlignYourBodyElement(drawable = item.drawable, text = item.text)
        }
    }

}
```

这里使用到了**LazyRow（懒加载）**而不是**Row**，原因就在于，**LazyRow** 只会渲染当前视图中的内容，有助于提高应用的性能。

### **运动收集网格**

![](./images/image-35.png)

```
data class FavoriteCollectionsData(
    @DrawableRes val drawable: Int,
    @StringRes val text: Int
)
@Composable
fun FavoriteCollectionsGrid(modifier: Modifier=Modifier)
{
    val favoriteCollectionsData= listOf(
        FavoriteCollectionsData(R.drawable.tomcat,R.string.username),
        FavoriteCollectionsData(R.drawable.tomcat,R.string.username),
        FavoriteCollectionsData(R.drawable.tomcat,R.string.username),
        FavoriteCollectionsData(R.drawable.tomcat,R.string.username),
        FavoriteCollectionsData(R.drawable.tomcat,R.string.username),
        FavoriteCollectionsData(R.drawable.tomcat,R.string.username),
    )

    LazyHorizontalGrid(
        rows = GridCells.Fixed(2),
        modifier=modifier.height(168.dp),
        contentPadding = PaddingValues(horizontal = 16.dp),
        horizontalArrangement = Arrangement.spacedBy(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        items(favoriteCollectionsData){
            item-> FavoriteCollectionCard(drawable = item.drawable, text = item.text, modifier = Modifier.height(80.dp))
        }
    }
}
```

**LazyHorizontalGrid**同样是**懒加载**的组件，指定了行数row之后会自动排列，然后使用items进行子元素生成

### 内容插槽

```
@Composable
fun HomeSection(
    @StringRes title: Int,
    modifier: Modifier = Modifier,
    content: @Composable () -> Unit
) {
    Column(modifier=modifier) {
        Text(
            text = stringResource(title),
            style = MaterialTheme.typography.titleMedium,
            modifier = Modifier
                .paddingFromBaseline(top = 40.dp, bottom = 16.dp)
                .padding(horizontal = 16.dp),
        )
        content()
    }
}
```

将内容传入**HomeSection**插槽来使用，增强代码的结构性。具体如下，并且要使用verticalScroll添加可滑动效果

```
//主体代码
@Composable
fun HomeScreen(modifier: Modifier = Modifier) {
    Column(
        modifier= modifier
            .fillMaxHeight()
            .background(color = Color(0xFFdbccb9))
            .verticalScroll(
                rememberScrollState()
            )
            .padding(bottom = 20.dp)
    ) {
        Spacer(modifier = Modifier.height(16.dp))
        SearchBar(Modifier.padding(horizontal = 16.dp))
        HomeSection(title = R.string.username) {
            AlignYourBodyRow()
        }

        HomeSection(title = R.string.username) {
            FavoriteCollectionsGrid()
        }

    }
}
```

### 导航栏

由于涉及到**横屏**和**竖屏**两种情况，导航栏得做两个

```kotlin
//竖屏
NavigationBar(
        modifier = modifier,
    ){
        NavigationBarItem(
            icon = {
                Icon(
                    imageVector = Icons.Default.Home,
                    contentDescription = stringResource(id = R.string.username)
                )
            },
            label = {
                Text(
                    text = stringResource(id = R.string.home)
                )
            },
            selected = true,
            onClick = {}
        )
        NavigationBarItem(
            icon = {
                Icon(
                    imageVector = Icons.Default.AccountCircle,
                    contentDescription = null
                )
            },
            label = {
                Text(
                    text = stringResource(id = R.string.profile)
                )
            },
            selected = false,
            onClick = {}
        )
    }
```

Jetpack Compose十分贴心，内置了底部导航栏的组件，可以直接使用。

```kotlin
//横屏
@Composable
private fun SootheNavigationRail(modifier: Modifier=Modifier)
{
    NavigationRail(
        modifier=modifier.padding(top = 8.dp, bottom = 8.dp),
        containerColor = MaterialTheme.colorScheme.background,
    ) {

        Column(
            modifier=modifier.fillMaxHeight(),
            verticalArrangement = Arrangement.Center,
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            NavigationRailItem(selected = false, onClick = { /*TODO*/ }, icon = {
                Icon(imageVector = Icons.Default.Home, contentDescription = null )
            },
                label = {
                    Text(text = stringResource(id = R.string.home))
                },

                )

            Spacer(modifier = Modifier.height(8.dp))

            NavigationRailItem(selected = false, onClick = { /*TODO*/ }, icon = {
                Icon(imageVector = Icons.Default.AccountCircle, contentDescription = null)
            },
                label = {
                    Text(text = stringResource(id = R.string.profile))
                }
            )

        }
    }
}
```

### 判断设备状态

官方的引用方式：[窗口大小类别  |  Jetpack Compose  |  Android Developers (google.cn)](https://developer.android.google.cn/develop/ui/compose/layouts/adaptive/window-size-classes?hl=zh-cn)

```kotlin
@OptIn(ExperimentalMaterial3AdaptiveApi::class)
@Composable
fun MyApp(
    windowSizeClass: WindowSizeClass = currentWindowAdaptiveInfo().windowSizeClass
) {
    // Perform logic on the size class to decide whether to show the top app bar.
    val showTopAppBar = windowSizeClass.windowHeightSizeClass != WindowHeightSizeClass.COMPACT

    // MyScreen knows nothing about window sizes, and performs logic based on a Boolean flag.
    MyScreen(
        showTopAppBar = showTopAppBar,
        /* ... */
    )
}
```

![](./images/image-36.png)

![](./images/image-37.png)

随意选择即可，我这里使用的是**高度判断**，并且只关心了**手机设备**

```kotlin
@Composable
fun MyApp(
    windowSizeClass: WindowSizeClass = currentWindowAdaptiveInfo().windowSizeClass
) {
    // Perform logic on the size class to decide whether to show the top app bar.
    when(windowSizeClass.windowHeightSizeClass)
    {
        WindowHeightSizeClass.MEDIUM,WindowHeightSizeClass.EXPANDED->{
            Scaffold(
                bottomBar = {
                    SootheBottomNavigation()
                }
            ) {
                padding ->  HomeScreen(Modifier.padding(padding))
            }
        }

        WindowHeightSizeClass.COMPACT->{
            Row {
                SootheNavigationRail()
                HomeScreen()
            }
        }
        
    }
}
```

如果是常规的竖屏情况下，可以使用**Scaffold**组件来进行快速创建包含各种导航栏的界面。

在横屏状态下，导航栏和主体内容应该是成**横向排列**的

### 总体代码

```kotlin
class MainActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            MyApplicationTheme {
                     MyApp()
            }
        }
    }
}
data class AlignYourBodyData(
    @DrawableRes val drawable:Int,
    @StringRes val text:Int
)

data class FavoriteCollectionsData(
    @DrawableRes val drawable: Int,
    @StringRes val text: Int
)
@Composable
fun FavoriteCollectionsGrid(modifier: Modifier=Modifier)
{
    val favoriteCollectionsData= listOf(
        FavoriteCollectionsData(R.drawable.tomcat,R.string.username),
        FavoriteCollectionsData(R.drawable.tomcat,R.string.username),
        FavoriteCollectionsData(R.drawable.tomcat,R.string.username),
        FavoriteCollectionsData(R.drawable.tomcat,R.string.username),
        FavoriteCollectionsData(R.drawable.tomcat,R.string.username),
        FavoriteCollectionsData(R.drawable.tomcat,R.string.username),
    )

    LazyHorizontalGrid(
        rows = GridCells.Fixed(2),
        modifier=modifier.height(168.dp),
        contentPadding = PaddingValues(horizontal = 16.dp),
        horizontalArrangement = Arrangement.spacedBy(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        items(favoriteCollectionsData){
            item-> FavoriteCollectionCard(drawable = item.drawable, text = item.text, modifier = Modifier.height(80.dp))
        }
    }
}

@Composable
fun AlignYourBodyRow(modifier: Modifier=Modifier)
{
    val alignYourBodyData=
        listOf(
            AlignYourBodyData(R.drawable.tomcat,R.string.username),
            AlignYourBodyData(R.drawable.tomcat,R.string.username),
            AlignYourBodyData(R.drawable.tomcat,R.string.username),
            AlignYourBodyData(R.drawable.tomcat,R.string.username),
            AlignYourBodyData(R.drawable.tomcat,R.string.username),
    )

    LazyRow(
        modifier=modifier,
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        contentPadding = PaddingValues(horizontal = 16.dp)
    ){
        items(alignYourBodyData){
            item-> AlignYourBodyElement(drawable = item.drawable, text = item.text)
        }
    }

}

@Composable
fun AlignYourBodyElement(
    modifier: Modifier=Modifier,
    @DrawableRes drawable:Int,
    @StringRes text:Int
)
{
    Column(
        horizontalAlignment = Alignment.CenterHorizontally,
        modifier = modifier
    ) {
        Image(painter = painterResource(id = drawable),
            contentDescription =null ,
            modifier= Modifier
                .size(88.dp)
                .clip(CircleShape),
            contentScale = ContentScale.Crop

        )
        Text(text = stringResource(id = text),
            modifier=Modifier.paddingFromBaseline(top = 24.dp, bottom = 8.dp)
        )
    }
}

@Composable
fun SearchBar(modifier: Modifier=Modifier)
{
    TextField(value = "",
        onValueChange = {},
        modifier= modifier
            .fillMaxWidth()
            .heightIn(min = 56.dp),
        leadingIcon = {
            Icon(painter = painterResource(id = R.drawable.search), contentDescription = null )
        },
        colors = TextFieldDefaults.colors(
            unfocusedLabelColor = MaterialTheme.colorScheme.surface,
            focusedContainerColor = MaterialTheme.colorScheme.surface,
        ),
        placeholder = {
            Text(text = stringResource(R.string.search))
        }
    )
}

@Composable
fun FavoriteCollectionCard(
    modifier: Modifier=Modifier,
    @DrawableRes drawable: Int,
    @StringRes text:Int
)
{
    Surface(
        shape = MaterialTheme.shapes.medium,
        modifier = modifier,
        color = MaterialTheme.colorScheme.surfaceVariant
    ) {
        Row (
            verticalAlignment = Alignment.CenterVertically,
            modifier=modifier.width(255.dp)
        ){
            Image(painter = painterResource(id = drawable),
                contentDescription =null,
                modifier=Modifier.size(80.dp),
                contentScale = ContentScale.Crop
            )
            Text(text = stringResource(id = text))

        }
    }
}
@Composable
fun HomeSection(
    @StringRes title: Int,
    modifier: Modifier = Modifier,
    content: @Composable () -> Unit
) {
    Column(modifier=modifier) {
        Text(
            text = stringResource(title),
            style = MaterialTheme.typography.titleMedium,
            modifier = Modifier
                .paddingFromBaseline(top = 40.dp, bottom = 16.dp)
                .padding(horizontal = 16.dp),
        )
        content()
    }
}
@Composable
fun HomeScreen(modifier: Modifier = Modifier) {
    Column(
        modifier= modifier
            .fillMaxHeight()
            .background(color = Color(0xFFdbccb9))
            .verticalScroll(
                rememberScrollState()
            )
            .padding(bottom = 20.dp)
    ) {
        Spacer(modifier = Modifier.height(16.dp))
        SearchBar(Modifier.padding(horizontal = 16.dp))
        HomeSection(title = R.string.username) {
            AlignYourBodyRow()
        }

        HomeSection(title = R.string.username) {
            FavoriteCollectionsGrid()
        }

    }
}

@Composable
private fun SootheBottomNavigation(modifier: Modifier=Modifier){
    NavigationBar(
        modifier = modifier,
    ){
        NavigationBarItem(
            icon = {
                Icon(
                    imageVector = Icons.Default.Home,
                    contentDescription = stringResource(id = R.string.username)
                )
            },
            label = {
                Text(
                    text = stringResource(id = R.string.home)
                )
            },
            selected = true,
            onClick = {}
        )
        NavigationBarItem(
            icon = {
                Icon(
                    imageVector = Icons.Default.AccountCircle,
                    contentDescription = null
                )
            },
            label = {
                Text(
                    text = stringResource(id = R.string.profile)
                )
            },
            selected = false,
            onClick = {}
        )
    }
}

@Composable
private fun SootheNavigationRail(modifier: Modifier=Modifier)
{
    NavigationRail(
        modifier=modifier.padding(top = 8.dp, bottom = 8.dp),
        containerColor = MaterialTheme.colorScheme.background,
    ) {

        Column(
            modifier=modifier.fillMaxHeight(),
            verticalArrangement = Arrangement.Center,
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            NavigationRailItem(selected = false, onClick = { /*TODO*/ }, icon = {
                Icon(imageVector = Icons.Default.Home, contentDescription = null )
            },
                label = {
                    Text(text = stringResource(id = R.string.home))
                },

                )

            Spacer(modifier = Modifier.height(8.dp))

            NavigationRailItem(selected = false, onClick = { /*TODO*/ }, icon = {
                Icon(imageVector = Icons.Default.AccountCircle, contentDescription = null)
            },
                label = {
                    Text(text = stringResource(id = R.string.profile))
                }
            )

        }
    }
}

@Composable
fun MyApp(
    windowSizeClass: WindowSizeClass = currentWindowAdaptiveInfo().windowSizeClass
) {
    
    when(windowSizeClass.windowHeightSizeClass)
    {
        WindowHeightSizeClass.MEDIUM,WindowHeightSizeClass.EXPANDED->{
            Scaffold(
                bottomBar = {
                    SootheBottomNavigation()
                }
            ) {
                padding ->  HomeScreen(Modifier.padding(padding))
            }
        }

        WindowHeightSizeClass.COMPACT->{
            Row {
                SootheNavigationRail()
                HomeScreen()
            }
        }
        
    }
}
@Preview(showBackground = true)
@Composable
fun MyPreview() {
    MyApplicationTheme {
        MyApp()
    }
}
```
